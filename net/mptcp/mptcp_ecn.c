/*
 *	MPTCP implementation - Coupled Congestion Conrol with ECN support
 *
 *	Initial Design & Implementation:
 *	Chi Xu <chix@sfu.ca>
 *	Jia Zhao <zhaojiaz@sfu.ca>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <net/tcp.h>
#include <net/mptcp.h>
//#include <math.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/tcp.h>
#include <linux/inet_diag.h>




/* Parameter from dctcp implementation */
#define DCTCP_MAX_ALPHA	1024U

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = DCTCP_MAX_ALPHA;
module_param(dctcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
		 "parameter for clamping alpha on loss");

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
};

/* fall back to our2 */
static struct tcp_congestion_ops mptcp_ccc; 


/* Parameter from our2 implementation */
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

static int GLB=0;
static u32 st_RTT=0;

/* TODO: parameter description */
module_param(alpha_scale_den, int, 0644);
MODULE_PARM_DESC(alpha_scale_den, "XXXXXX");
module_param(alpha_scale_num, int, 0644);
MODULE_PARM_DESC(alpha_scale_num, "XXXXXX");
module_param(alpha_scale, int, 0644);
MODULE_PARM_DESC(alpha_scale, "XXXXX");


struct wvegas {
	u32	beg_snd_nxt;	/* right edge during last RTT */
	u8	doing_wvegas_now;/* if true, do wvegas for this RTT */
	u16	cnt_rtt;		/* # of RTTs measured within last RTT */
	u32 sampled_rtt; /* cumulative RTTs measured within last RTT (in usec) */
	u32	base_rtt;	/* the min of all wVegas RTT measurements seen (in usec) */
    int trigger;
	u64 instant_rate; /* cwnd / srtt_us, unit: pkts/us * 2^16 */
	u64 weight; /* the ratio of subflow's rate to the total rate, * 2^16 */
	int no_alpha; /* alpha for each subflows */
	u32 queue_delay; /* queue delay*/
};



/* legacy function from dctcp */

static void dctcp_reset(const struct tcp_sock *tp, struct dctcp *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}

static u32 dctcp_ssthresh(struct sock *sk)
{
	const struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void dctcp_ce_state_0_to_1(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void dctcp_ce_state_1_to_0(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static void dctcp_update_alpha(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;

		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		/* For avoiding denominator == 1. */
		if (ca->acked_bytes_total == 0)
			ca->acked_bytes_total = 1;

		/* alpha = (1 - g) * alpha + g * F */
		ca->dctcp_alpha = ca->dctcp_alpha -
				  (ca->dctcp_alpha >> dctcp_shift_g) +
				  (ca->acked_bytes_ecn << (10U - dctcp_shift_g)) /
				  ca->acked_bytes_total;

		if (ca->dctcp_alpha > DCTCP_MAX_ALPHA)
			/* Clamp dctcp_alpha to max. */
			ca->dctcp_alpha = DCTCP_MAX_ALPHA;

		dctcp_reset(tp, ca);
	}
}

static void dctcp_state(struct sock *sk, u8 new_state)
{
	if (dctcp_clamp_alpha_on_loss && new_state == TCP_CA_Loss) {
		struct dctcp *ca = inet_csk_ca(sk);

		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
	}
}

static void dctcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct dctcp *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_DELAYED_ACK:
		if (!ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 1;
		break;
	case CA_EVENT_NON_DELAYED_ACK:
		if (ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 0;
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
		dctcp_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		dctcp_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		dctcp_update_ack_reserved(sk, ev);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static size_t dctcp_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_DCTCPINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(info, 0, sizeof(struct tcp_dctcp_info));
		if (inet_csk(sk)->icsk_ca_ops != &mptcp_ccc) {
			info->dctcp.dctcp_enabled = 1;
			info->dctcp.dctcp_ce_state = (u16) ca->ce_state;
			info->dctcp.dctcp_alpha = ca->dctcp_alpha;
			info->dctcp.dctcp_ab_ecn = ca->acked_bytes_ecn;
			info->dctcp.dctcp_ab_tot = ca->acked_bytes_total;
		}

		*attr = INET_DIAG_DCTCPINFO;
		return sizeof(*info);
	}
	return 0;
}



static void mptcp_wvegas_pkts_acked(const struct sock *sk, s32 rtt_us)
{
	struct wvegas *wvegas = inet_csk_ca(sk);
	u32 vrtt, rtt;

	if (rtt_us < 0)
		return;

	vrtt = rtt_us + 1;

	if (vrtt < wvegas->base_rtt)
		wvegas->base_rtt = vrtt;

	wvegas->sampled_rtt += vrtt;
	wvegas->cnt_rtt++;

	//pr_warning("sampled_rtt is %u, cnt_rtt is %u", wvegas->sampled_rtt, wvegas->cnt_rtt);
    rtt = wvegas->sampled_rtt / ((u32) wvegas->cnt_rtt);
    
    if (rtt > 10 * wvegas->base_rtt && GLB == 0){
    	GLB=1;
        wvegas->trigger=1;
        st_RTT = rtt;
    }

}

/* Scaling is done in the numerator with alpha_scale_num and in the denominator
 * with alpha_scale_den.
 *
 * To downscale, we just need to use alpha_scale.
 *
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den ^ 2)
 */


struct mptcp_ccc {
	u64	alpha;
	bool	forced_update;
};

static inline int mptcp_ccc_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;
}

static inline u64 mptcp_get_alpha(const struct sock *meta_sk)
{
	return ((struct mptcp_ccc *)inet_csk_ca(meta_sk))->alpha;
}

static inline void mptcp_set_alpha(const struct sock *meta_sk, u64 alpha)
{
	((struct mptcp_ccc *)inet_csk_ca(meta_sk))->alpha = alpha;
}

static inline u64 mptcp_ccc_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline bool mptcp_get_forced(const struct sock *meta_sk)
{
	return ((struct mptcp_ccc *)inet_csk_ca(meta_sk))->forced_update;
}

static inline void mptcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct mptcp_ccc *)inet_csk_ca(meta_sk))->forced_update = force;
}

static void mptcp_ccc_recalc_alpha(const struct sock *sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
//  const struct wvegas *wvegas66 = inet_csk_ca(sk);
//  u64 rtt_div=1, tyler=1;
	int best_cwnd = 0, best_rtt = 0, can_send = 0;
	u64 max_numerator = 0, sum_denominator = 0, alpha = 1;

	if (!mpcb)
		return;

	/* Only one subflow left - fall back to normal reno-behavior
	 * (set alpha to 1)
	 */
	if (mpcb->cnt_established <= 1)
		goto exit;

	/* Do regular alpha-calculation for multiple subflows */

	/* Find the max numerator of the alpha-calculation */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
        struct wvegas *wvegas66 = inet_csk_ca(sub_sk);
		u64 tmp, tyler, tyler1, rtt_div;
        rtt_div = div64_u64((u64)wvegas66->base_rtt, (u64)sub_tp->srtt_us);

		if (!mptcp_ccc_sk_can_send(sub_sk)) {
			continue;
		}


		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */
        tyler = 100*(u64)(1+(10*rtt_div - 5)+50*(10*rtt_div - 5)*(10*rtt_div - 5)+17*(10*rtt_div - 5)*(10*rtt_div - 5)*(10*rtt_div - 5));
        tyler1 = 100*(u64)(1+1+(10*rtt_div - 5)+50*(10*rtt_div - 5)*(10*rtt_div - 5)+17*(10*rtt_div - 5)*(10*rtt_div - 5)*(10*rtt_div - 5));
		tmp = div64_u64((u64)div64_u64(2*tyler,tyler1) * mptcp_ccc_scale(sub_tp->snd_cwnd,
				alpha_scale_num), (u64)sub_tp->srtt_us * sub_tp->srtt_us);

		if (tmp >= max_numerator) {
			max_numerator = tmp;
			best_cwnd = sub_tp->snd_cwnd;
			best_rtt = sub_tp->srtt_us;
		}
                  
//      mptcp_wvegas_pkts_acked(sub_sk, sub_tp->srtt_us);
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
		mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
//      struct wvegas *wvegas66 = inet_csk_ca(sk);
//      rtt_div=div64_u64((u64)wvegas66->base_rtt, (u64)sub_tp->srtt_us);

		if (!mptcp_ccc_sk_can_send(sub_sk)) {
			continue;
		}

		sum_denominator += div_u64(
				mptcp_ccc_scale(sub_tp->snd_cwnd,
						alpha_scale_den) * best_rtt,
						sub_tp->srtt_us);
	}

	sum_denominator *= sum_denominator;
	if (unlikely(!sum_denominator)) {
		pr_err("%s: sum_denominator == 0, cnt_established:%d\n",
		       __func__, mpcb->cnt_established);
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			pr_err("%s: pi:%d, state:%d\n, rtt:%u, cwnd: %u",
			       __func__, sub_tp->mptcp->path_index,
			       sub_sk->sk_state, sub_tp->srtt_us,
			       sub_tp->snd_cwnd);
		}
	}

//        u64 tyler;
        
	alpha = div64_u64(mptcp_ccc_scale(best_cwnd, alpha_scale_num),  sum_denominator);


	if (unlikely(!alpha))
		alpha = 1;

exit:
	mptcp_set_alpha(mptcp_meta_sk(sk), alpha);

        
}


static void mptcp_ccc_ecn_init(struct sock *sk)
{
	if (mptcp(tcp_sk(sk))) {
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
		mptcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
	/* If we do not mptcp, behave like reno: return */

	/* here from wvegas */
    struct wvegas *wvegas = inet_csk_ca(sk);

	wvegas->base_rtt = 0x7fffffff;
    wvegas->trigger = 0;
    /* end from wvegas */

    /* here from dctcp */
    const struct tcp_sock *tp = tcp_sk(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {
		struct dctcp *ca = inet_csk_ca(sk);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);

		ca->delayed_ack_reserved = 0;
		ca->ce_state = 0;

		dctcp_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for DCTCP.
	 */

	inet_csk(sk)->icsk_ca_ops = &mptcp_ccc;
	INET_ECN_dontxmit(sk);

	/* end from dctcp*/
}


static void mptcp_ccc_init(struct sock *sk)
{
	if (mptcp(tcp_sk(sk))) {
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
		mptcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
	/* If we do not mptcp, behave like reno: return */
        struct wvegas *wvegas = inet_csk_ca(sk);

	wvegas->base_rtt = 0x7fffffff;
    wvegas->trigger = 0;
}

static void mptcp_ccc_ecn_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{	
	/* from dctcp */
	switch (event) {
	case CA_EVENT_ECN_IS_CE:
		dctcp_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		dctcp_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		dctcp_update_ack_reserved(sk, event);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}

	/*from mptcp */
	if (event == CA_EVENT_LOSS)
		mptcp_ccc_recalc_alpha(sk);
}


static void mptcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		mptcp_ccc_recalc_alpha(sk);
}


static void mptcp_ccc_ecn_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;

	mptcp_set_forced(mptcp_meta_sk(sk), 1);

	if (dctcp_clamp_alpha_on_loss && ca_state == TCP_CA_Loss) {
		struct dctcp *ca = inet_csk_ca(sk);

		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
	}

}


static void mptcp_ccc_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))
		return;

	mptcp_set_forced(mptcp_meta_sk(sk), 1);
}

static void mptcp_ccc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
 // struct wvegas *wvegas = inet_csk_ca(sk);
	int snd_cwnd;


    struct wvegas *wvegas = inet_csk_ca(sk);

    mptcp_wvegas_pkts_acked(sk, tp->srtt_us);
      

    if ((u32)wvegas->sampled_rtt / wvegas->cnt_rtt > 10 * wvegas->base_rtt && wvegas->trigger == 0 && GLB == 1 && ((u32)wvegas->sampled_rtt / wvegas->cnt_rtt - st_RTT) < wvegas->base_rtt) {
            tp->snd_cwnd = 0;
    }

	if (!mptcp(tp)) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		mptcp_ccc_recalc_alpha(sk);
		return;
	}

	if (mptcp_get_forced(mptcp_meta_sk(sk))) {
		mptcp_ccc_recalc_alpha(sk);
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
	}

	if (mpcb->cnt_established > 1) {
		u64 alpha = mptcp_get_alpha(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * was not yet attached to the sock, and thus
		 * initializing alpha failed.
		 */
		if (unlikely(!alpha))
			alpha = 1;

		snd_cwnd = (int) div_u64 ((u64) mptcp_ccc_scale(1, alpha_scale),
						alpha);

		/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
		 * Thus, we select here the max value.
		 */
		if (snd_cwnd < tp->snd_cwnd)
			snd_cwnd = tp->snd_cwnd;
	} else {
		snd_cwnd = tp->snd_cwnd;
	}

	if (tp->snd_cwnd_cnt >= snd_cwnd) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			tp->snd_cwnd++;
			mptcp_ccc_recalc_alpha(sk);
		}

		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}

static struct tcp_congestion_ops mptcp_ccc_ecn = {
	.init		= mptcp_ccc_ecn_init,    /* DONE: (m) mptcp_ccc_init (d) dctcp_init */
	.in_ack_event   = dctcp_update_alpha, /* DONE */
	.ssthresh	= dctcp_ssthresh, /* DONE: (m) tcp_reno_ssthresh */
	.cong_avoid	= mptcp_ccc_cong_avoid, /* DONE: (d) tcp_reno_cong_avoid */
	.cwnd_event	= mptcp_ccc_ecn_cwnd_event,  /* DONE: (d) dctcp_cwnd_event */
	.set_state	= mptcp_ccc_ecn_set_state, /* DONE: (d) dctcp_state */
	.get_info	= dctcp_get_info,
	.flags		= TCP_CONG_NEEDS_ECN, /* DONE */
	.owner		= THIS_MODULE,
	.name		= "mptcp_ccc_ecn",
};

static struct tcp_congestion_ops mptcp_ccc = {
	.init		= mptcp_ccc_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= mptcp_ccc_cong_avoid,
	.cwnd_event	= mptcp_ccc_cwnd_event,
	.set_state	= mptcp_ccc_set_state,
	.owner		= THIS_MODULE,
	.name		= "mptcp_ccc",
};


static int __init mptcp_ccc_ecn_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_ccc) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mptcp_ccc_ecn);
}

static void __exit mptcp_ccc_ecn_unregister(void)
{
	tcp_unregister_congestion_control(&mptcp_ccc_ecn);
}

module_init(mptcp_ccc_ecn_register);
module_exit(mptcp_ccc_ecn_unregister);

MODULE_AUTHOR("Chi Xu, Jia Zhao");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP Coupled Congestion Control with ECN support");
MODULE_VERSION("0.1");