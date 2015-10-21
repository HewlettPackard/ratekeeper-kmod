/*
 * Copyright (c) 2015 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <linux/etherdevice.h>

#include "../include/monitor.h"
#include "../include/messaging_kernel.h"

/* Monitor status variable states */
#define MON_FREE                   0
#define MON_ACQUIRED               1

/* Timing definitions */
#define TICKS_PER_US               16       /* 1us = 1/64x10^3 ticks
                                             * for info: <net/pkt_sched.h> */
#define TIME_FACTOR                10       /* The code uses this factor
                                             * to convert time units. e.g.
                                             * 1s = 2^10ms */

/* Maximum congestion severity */
#define MAX_CONGESTION_SEVERITY     300
#define SEVERITY_INCREASE_THRESHOLD 3
#define SEVERITY_DECREASE_THRESHOLD 10


/* This is the instance number used to identify the
q * monitor that accumulates all other measurements */
#define ACC_INSTANCE                0

/* Returns the exponent of the largest previous number in base 2.
 * For example, given x = 9, the macro returns 3 */
#define FLSE(x)                    (fls(x)-1)
/* Given an interval in ns, returns the ammount of ticks in this interval */
#define US2TICKS(x)                (x?(x<<(FLSE(TICKS_PER_US))):0)
/* Given an interval in ns, returns the exponent of the largest
   previous number in base 2. For example, given x = 1050, the
   macro returns 20. */
#define US2SHIFT(x)                (x?(FLSE(US2TICKS(x))-FLSE(TICKS_PER_US)):0)

/* Ratekeeper hook */
extern int (*rk_hook) (struct sk_buff *skb, int at_ifindex, int *instance);

/**
 *  Monitor instance structure
 *
 *  @status: possible values are MON_FREE when not in use or
 *  MON_ACQUIRED when the monitor was acquired by an interface
 *  @ifindex: the index of the interface being monitored by this
 *  instance. ACC_IFINDEX for the monitor instance ACC_INSTANCE.
 *  Writers must acquire the monitor_cfg_lock to change.
 *  @is_tnic: flag indicating if the monitor is associated with a tnic.
 *  For tnics the monitor module will also update the monitor instance 0, 
 *  which monitor the aggregate rate of all tnic monitors.
 *  @rate: rate measured in the last interval measurement period
 *  @byte_ctr: byte counter, for rate measurement
 *  @limit: This is the max rate for a vnic or the min rate for a tnic.
 *  if a vnic rate is higher than this value , the monitor will
 *  notify userspace daemon. When the accumulator (monitor instance 0)
 *  exceeds the link highmark the limit of all tnics are used to determine
 *  if the userspace daemon should be notified. The daemon is only notified
 *  if a congestion feedback needs to be sent.
 *  @mac: mac address of the last packet seen at the monitor.
 *  @prev: time when the last measurement interval started
 */
struct monitor_instance {
	char           status;
	int            ifindex;
	int            is_tnic; // 1 if tnic; 0 otherwise
	/* Rate monitoring vars */
	u64            byte_ctr;
	int            pkt_ctr;
	u64            limit;   // min (for tnic) or max (for vnic) rate 
	u64            rate;
	uint8_t        mac[ETH_ADDR_LEN];
	/* Timing */
	psched_time_t  prev;

	/* FB Rate limiting */
	u64            last_fb;

	/* Congestion severity tracking:
	   Severity is incremented when congestion persists on consecutive
	   monitor intervals, as this is an indication that the previous 
	   feedback was not sufficient to contain congestion.
	   Severity is decremented after we see a number N of consecutive
	   monitor intervals without congestion, where N is the current
	   value of severity.
	*/
	u32            severity;
	int            count_high;
	int            count_low;

	spinlock_t     lock;
};


static void print_monitor(struct monitor_instance *mi) {

    printk(KERN_ALERT
            "RK: mac: %02x:%02x:%02x:%02x:%02x,%02x, "
            "status: %d, "
            "ifindex: %d, "
            "is_tnic: %d, "
            "byte_ctr: %lld, "
            "pkt_ctr: %d, "
            "limit: %lld, "
            "rate: %lld, "
            "prev: %lld, "
            "last_fb: %lld, "
            "severity: %u, "
            "count_high: %d, "
            "count_low: %d\n",
            mi->mac[0] & 0xff, mi->mac[1] & 0xff, mi->mac[2] & 0xff, mi->mac[3] & 0xff, mi->mac[4] & 0xff, mi->mac[5] & 0xff,
            //mi->mac[0], mi->mac[1],
            mi->status,
            mi->ifindex,
            mi->is_tnic,
            mi->byte_ctr,
            mi->pkt_ctr,
            mi->limit,
            mi->rate,
            mi->prev,
            mi->last_fb,
            mi->severity,
            mi->count_high,
            mi->count_low);
}

/* Monitors. Each monitor M is protected by M->lock */
static struct monitor_instance  monitors[MON_INSTANCES];

/* Global configs and variables are protected by monitor_cfg_lock */
static spinlock_t monitor_cfg_lock;

static int        monitor_cfg_acquired; /* Number of ACQUIRED instances */

/* Global timing variables */
static psched_time_t monitor_interval;   /* Global measurement interval */
static int           monitor_interval_s; /* Base 2 exp of monitor_interval */
static atomic64_t    monitor_clock;      /* Global monitor clock */

/* TODO: implement a GET request to retrieve the following values */
static atomic_t      monitor_no_feedbacks;
static atomic_t      monitor_no_congestions;

static inline int increment_severity(struct monitor_instance *m)
{
	m->count_low = 0;

	if ( m->severity >= MAX_CONGESTION_SEVERITY )
		return MAX_CONGESTION_SEVERITY;

        m->count_high++;
	if ( m->count_high > SEVERITY_INCREASE_THRESHOLD) {
		m->severity++;
		m->count_high = 0;
	}

	return m->severity;
}

static inline int decrement_severity(struct monitor_instance *m)
{
	m->count_high = 0;

	if ( m->severity <= 0 )
		return 0;

	m->count_low++;
	if ( (m->severity > 0) && (m->count_low > SEVERITY_DECREASE_THRESHOLD) ) {
		m->severity--;
		m->count_low = 0;
	}

	return m->severity;
}

/* Check if needs to notify user space of congestion detection */
static inline int monitor_congestion(struct monitor_instance *m)
{
	int ifindex = m->ifindex;
        struct monitor_instance *t;
	int aggregate_severity_flag;
	int highmark;
	int idx;

	/* nothing to be done for tnics */
	/* they will be handled when processing the accumulator */
	if (m->is_tnic)
		return 0;

	/* vnic case */
	if (ifindex != ACC_IFINDEX) {
		if (m->rate > m->limit) {
		    //printk(KERN_ALERT "RK: Congestion!!!! rate=%llu limit=%llu\n", m->rate * 8, m->limit * 8);
			rk_upcall_congestion(m->ifindex, m->mac, m->severity);
			increment_severity(m);
			atomic_inc(&monitor_no_congestions);
		} else {
			decrement_severity(m);
		}
		return 0;
	}


	/* accumulator case */
	if (m->rate > m->limit) {
		highmark = 1;
		printk(KERN_ALERT "RK: Ratekeeper HIGHMARK reached: rate=%llu limit=%llu", m->rate * 8, m->limit * 8);
	}
	else {
		/* use the severity field of the accumulator as a flag */
		/* if any tnic has severity > 0 this flag is 1; otherwise 0 */
		if ( m->severity == 0 )
			/* we can only return if we do not need to update */
			/* severity values in any of the tnics */
			return 0;
		highmark = 0;
	}	

        return 0;

	aggregate_severity_flag = 0;
	for ( idx = 1; idx < MON_INSTANCES; idx++ ) {
		t = &monitors[idx];
		if ( (t->status  != MON_FREE) && (t->is_tnic) ) {
			if ( highmark && (t->rate > (t->limit * 1.10)) ) {
				rk_upcall_congestion(t->ifindex,
						     t->mac, 
						     t->severity);
	  			increment_severity(t);
				aggregate_severity_flag = 1;
				atomic_inc(&monitor_no_congestions);
			}
			else if (decrement_severity(t) > 0) {
				aggregate_severity_flag = 1;
			}
		}
	}
	m->severity = aggregate_severity_flag;

	return 0;
}

/* Notify feedback reception */
static inline int monitor_feedback(int ifindex, unsigned int severity)
{
	atomic_inc(&monitor_no_feedbacks);
	return rk_upcall_feedback(ifindex, severity);
}

/* Returns clock set to last monitor_clock value if monitor_interval time 
 * has not passed, otherwise returns clock set to "now" (expressed
 * in steps of monitor_interval) */
static inline psched_time_t clock_step (psched_time_t now) {
	/* the atomic64 lock seems redundant. TODO: remove it */
	psched_time_t clock = (u64) atomic64_read(&monitor_clock);

	if (likely(clock + monitor_interval > now))
		return clock;

	while (clock + monitor_interval < now)
		clock += monitor_interval;

	atomic64_set(&monitor_clock, clock);
	return clock;
}

static int monitor_update(struct sk_buff *skb, int instance, psched_time_t now)
{

    //printk(KERN_ALERT "RK: Inside monitor_update...\n");
	struct monitor_instance *m = &monitors[instance];
	struct ethhdr *ethhdr;
	psched_time_t clock;
	int ret;
	u64 rate;
	u64 n;

	spin_lock_bh(&m->lock);
	/* If not the ACC monitor and its status is MON_FREE, skip it */
	if (m->ifindex != ACC_IFINDEX && m->status == MON_FREE) {
		spin_unlock_bh(&m->lock);
		return MON_FREED;
	}

	clock = clock_step(now);
    //printk(KERN_ALERT "RK: ifindex: %d monitor_interval: %lld m->prev: %lld clock: %lld diff: %lld diff_frac: %lld pkts: %d\n", m->ifindex, monitor_interval, m->prev, clock, clock - m->prev, (clock - m->prev)/monitor_interval, m->pkt_ctr);
    /* If monitor_interval time has not passed yet?? */

	if (likely(m->prev == clock)) {
        m->pkt_ctr = m->pkt_ctr;
		m->byte_ctr += skb->len;
		m->pkt_ctr  += 1;
        //printk(KERN_ALERT "RK: if\n");
	}
    /* If twice the monitor_interval has not passed?? */
	else if (likely(now < (m->prev + (monitor_interval << 1)))) {
        //printk(KERN_ALERT "RK: elif\n");
		m->prev = clock;
		rate = m->byte_ctr >> (monitor_interval_s);
        //printk(KERN_ALERT "RK: rate: %lld monitor_interval_s: %d\n", rate, monitor_interval_s);
		/* Moving average */
		m->rate     = (rate + m->rate) >> 1;
	
		//printk(KERN_ALERT "RK: %d: rate=%llu threshold=%llu\n", m->ifindex, 
        //        (u64) bypus2mbps(m->rate), (u64) bypus2mbps(m->limit));  // (u64) (m->rate)/0.125
        //print_monitor(m);
		//printk(KERN_ALERT "RK: MARIO: ifindex %d: rate=%lld bytes=%lld pkts=%d\n", m->ifindex, m->rate, m->byte_ctr, m->pkt_ctr);

		if (!m->is_tnic) 
			monitor_congestion(m);

        /*reset byte and packet counter for next interval*//*MARIO WHY??*/
		m->byte_ctr = skb->len;
		m->pkt_ctr  = 1;
	}
	// TODO: when handling the accumulator we need to update all tnics here too
	else { /* A long time have passed, restart measurement */

        //printk(KERN_ALERT "RK: else\n");
		if (m->severity >= 1) {
			/* number of intervals elapsed since last message */
			n = (clock - m->prev) / monitor_interval;

			/* Number of times we would decrease severity */
			n = n / SEVERITY_DECREASE_THRESHOLD;

			if (n < m->severity)
				m->severity -= n;
			else
				m->severity = 0;

		}
		m->count_high = 0;
		m->count_low = 0;

		m->byte_ctr  = skb->len;
		m->pkt_ctr   = 1;
		m->rate      = 0;
		m->prev      = clock;
	}

	/* The right thing to do here is to use skb_mac_header(), but some
	 * pkts don't have skb->mac_header set. TODO: figure out how to
	 * set this field after calling pskb_may_pull. */
	ethhdr = (struct ethhdr *) skb->data;
	if (skb->mac_len)
		ethhdr = (struct ethhdr *) skb_mac_header(skb);
	memcpy(&m->mac, ethhdr->h_source, ETH_ADDR_LEN);

	ret = MON_UPDATED;
	if (!m->is_tnic)
		ret |= MON_THRESHOLD; /* If the MON_THRESHOLD flag is not set,
				       * then the accumulator will be updated */

	spin_unlock_bh(&m->lock);

	return ret;
}

/* Called with monitor_cfg_lock */
static int monitor_get_instance(int ifindex, int *instance)
{
	int i;
	if (monitor_cfg_acquired < MON_INSTANCES) {
		for (i = 1; i < MON_INSTANCES; i++) {
			if (monitors[i].ifindex == ifindex) {
				*instance = i;
				 printk(KERN_WARNING "RK: monitor_get_instance (A) (ifindex=%d) (monitor_cfg_acquired=%d)\n",
				       ifindex, monitor_cfg_acquired);
				return MON_SET;
			}
		}
	}
	printk(KERN_WARNING "RK: monitor_get_instance (B) (ifindex=%d) (monitor_cfg_acquired=%d)\n",
	       ifindex, monitor_cfg_acquired);
	return MON_UNAVAILABLE;
}

static int __monitor_get_rate(struct monitor_instance *m)
{
	if (m->status == MON_ACQUIRED)
		return m->rate;
	return 0;
}

/* Instanciates a new monitor
 * Called with monitor_cfg_lock
 *
 * Threshold = 0 means "don't generate
 * notification for this monitor"  */
static int __monitor_set(int ifindex, u32 limit, int is_tnic)
{

	int i;

    /* This case handles the aggregate link highmark */
	if ( ifindex == ACC_IFINDEX ) {
		printk(KERN_ALERT "RK: Ratekeeper setting aggregate link highmark to %d Mb/s\n", limit * 8);
		spin_lock_bh(&monitors[ACC_INSTANCE].lock);
		monitors[ACC_INSTANCE].limit = limit;
		spin_unlock_bh(&monitors[ACC_INSTANCE].lock);
		return MON_SET;
	}

	if ( is_tnic ) {
		printk(KERN_ALERT "RK: Ratekeeper setting TNIC (ifindex=%d) rate to %d Mb/s\n", 
		       ifindex, limit * 8);
	}
	else {
		printk(KERN_ALERT "RK: Ratekeeper setting VNIC (ifindex=%d) rate to %d Mb/s\n", 
		       ifindex, limit * 8);
	}
	/* Looking for an existing monitor */
	for (i = 1; i < MON_INSTANCES; i++) {
		spin_lock_bh(&monitors[i].lock);
		if (monitors[i].ifindex  == ifindex &&
			monitors[i].status == MON_ACQUIRED) {
			monitors[i].limit = limit;
            printk(KERN_ALERT "RK: Looking for an existing monitor\n");
            print_monitor(&monitors[i]);
			spin_unlock_bh(&monitors[i].lock);
			return MON_SET;
		}
		spin_unlock_bh(&monitors[i].lock);
	}
	/* If not found, then set a new one */
	if (monitor_cfg_acquired < MON_INSTANCES) {
		for (i = 1; i < MON_INSTANCES; i++) {
			spin_lock_bh(&monitors[i].lock);
			if (monitors[i].status  == MON_FREE) {
				monitors[i].status    = MON_ACQUIRED;
				monitors[i].ifindex   = ifindex;
				monitors[i].limit     = limit;
				monitors[i].is_tnic   = is_tnic;
				monitor_cfg_acquired++;
                printk(KERN_ALERT "RK: not found, then set a new one\n");
                print_monitor(&monitors[i]);
				printk(KERN_WARNING "RK: __monitor_set (ifindex=%d)(monitor_cfg_acquired=%d)\n",
				       ifindex, monitor_cfg_acquired);
				spin_unlock_bh(&monitors[i].lock);
				return MON_SET;
			}
			spin_unlock_bh(&monitors[i].lock);
		}
	}
	return MON_UNAVAILABLE;
}

/* Release a monitor instance
 * Called with monitor_cfg_lock */
static int __monitor_unset(int ifindex)
{
	int i;

	for (i = 1; i < MON_INSTANCES; i++) {
		spin_lock_bh(&monitors[i].lock);
		if (monitors[i].ifindex  == ifindex) {
			// clear state of monitor i except for its lock
			memset(&monitors[i], 0, 
				(char *)&monitors[i].lock - 
				(char *)&monitors[i]);
			monitor_cfg_acquired--;
			printk(KERN_WARNING "RK: __monitor_unset (ifindex=%d)(monitor_cfg_acquired=%d)\n",
				ifindex, monitor_cfg_acquired);
			spin_unlock_bh(&monitors[i].lock);
			return MON_UNSET;
		}
		spin_unlock_bh(&monitors[i].lock);
	}
	return MON_NOT_FOUND;
}

/* Verifies if a skb carries a rk feedback message */
static inline int eth_proto_rk(struct sk_buff *skb)
{
	if (eth_hdr(skb) && skb->mac_len) {
		return (ntohs(eth_hdr(skb)->h_proto) == ETH_P_RK);
    }
	return 0;
}


/**
 * Parameters of monitor_hook:
 *
 * @skb: packet's socket buffer structure
 * @at_ifindex: ifindex of the net device this packet was intercepted
 * @instance: the caller remembers which monitor instance is in use for the
 *            net device @at_ifindex. This is the monitor instance index.
 *
 * Basic algorithm:
 *  - Does the caller know the monitor instance? (i.e. is instance != 0?)
 *    Y - Update monitor;
 *        Update *instance if monitor was released or stolen. i.e.
 *        if status == MON_FREED or at_ifindex != monitor ifindex then
 *        set instance = 0
 *    N - Look for the changed monitor instance. Found?
 *        Y - Set the instance number.
 *            Update monitor
 *        N - Print error on kernel log and return
 */
static int monitor_hook(struct sk_buff *skb, int at_ifindex, int *instance)
{
	//printk(KERN_WARNING "RK: Inside monitor_hook...\n");
	int ret = MON_NOT_FOUND, ifindex = 0;
	psched_time_t now;
	struct rkfb *fb_msg;

	/* Q: Is this code ever called with bh interrupts disabled? */

	/* Making sure that we have at least ETH_HLEN bytes (eth header)
	 * in the main data area */
	if (!pskb_may_pull(skb, ETH_HLEN + sizeof(struct rkfb))) {
		/* It seems the condition above is true for rk feedback
		 * messages. TODO: answer why? (however, it seems to be true
		 * only at the first time the packet is intercepted) */
		return MON_ERROR;
	}

	ifindex = skb->dev->ifindex;

	/* pointer to feedback message payload */
	fb_msg = (struct rkfb *) (skb->data + ETH_HLEN);

    int feed = eth_proto_rk(skb);
    if (feed > 0) {
        printk(KERN_WARNING "RK: ifindex: %d at_index: %d feedback?: %d\n", ifindex, at_ifindex, feed);
    }

	/* Can we intercept this msg? AND Is this skb a rk feedback msg? */
	/* In other words, only check for rk feedbacks if the packet was
	 * intercepted at the interface it is supposed to be delivered. */
	//if (ifindex == at_ifindex && eth_proto_rk(skb)) {
	if (eth_proto_rk(skb)) {
		if ((ret = monitor_feedback(ifindex, ntohl(fb_msg->severity))) > 0)
			return MON_UPCALL;	/* With this return code, the caller
						 * is supposed to return TC_ACT_STOLEN
						 * to kernel.  TODO: do we need to
						 * free the skb?  if so, we have a mem
						 * leak here */
		return ret;
	}

	/* Algorithm */
	now = psched_get_time();
	if (*instance != 0 && *instance < MON_INSTANCES) {
		if ((ret = monitor_update(skb, *instance, now)) == MON_UPDATED)
			monitor_update(skb, ACC_INSTANCE, now);
		else if (ret == MON_FREED)
			*instance = 0;
		return ret;
	}

	spin_lock_bh(&monitor_cfg_lock);

	printk(KERN_WARNING "RK: Looking up monitor for interface index %d name %s from hook at index %d\n", 
		ifindex, skb->dev->name, at_ifindex);
	if ((ret = monitor_get_instance(ifindex, instance)) != MON_UNAVAILABLE)
		if ((ret=monitor_update(skb, *instance, now)) == MON_UPDATED)
			monitor_update(skb, ACC_INSTANCE, now);

	spin_unlock_bh(&monitor_cfg_lock);

	if (ret == MON_NOT_FOUND) {
		printk(KERN_WARNING "RK: no monitor available for ifindex %d (monitor_cfg_acquired=%d)\n",
		       ifindex, monitor_cfg_acquired);
	}
	return ret;
}

static inline void monitor_instance_init(struct monitor_instance *m)
{
	memset(m, 0, sizeof(struct monitor_instance));
	spin_lock_init(&m->lock);
	m->status = MON_FREE;
}

int __init monitor_init(uint32_t RK_INTERVAL, uint32_t highmark)
{
	int i;

    printk(KERN_ALERT "RK: Inside monitor_init....\n");
	if (rk_hook)
		return -1;

	/* Monitor instances initialization  */
	for (i = 0; i < MON_INSTANCES; i++)
		monitor_instance_init(&monitors[i]);
	/* Global monitor instance initialization */
	monitors[ACC_INSTANCE].status    = MON_ACQUIRED;
	monitors[ACC_INSTANCE].limit     = highmark;
	monitors[ACC_INSTANCE].is_tnic   = 0;
	monitors[ACC_INSTANCE].ifindex   = ACC_IFINDEX;

	/* Monitor configs initialization */
	spin_lock_init(&monitor_cfg_lock);
	monitor_cfg_acquired = 1;

	/* Timing initialization */
	if (RK_INTERVAL < 1) {
		printk(KERN_ALERT "RK: The minimum time interval is 1us.");
		RK_INTERVAL = 1;
	}
	monitor_interval   = US2TICKS(RK_INTERVAL);
	monitor_interval_s = US2SHIFT(RK_INTERVAL);
	atomic64_set(&monitor_clock, psched_get_time());

	atomic_set(&monitor_no_feedbacks, 0);
	atomic_set(&monitor_no_congestions, 0);

	/* Hook initialization */
    printk(KERN_ALERT "RK: Initializing rk_hook...\n");
	rk_hook = monitor_hook;

	return 0;
}

void __exit monitor_exit(void)
{
	rk_hook = NULL;
}

/* User functions */

int monitor_get_instances()
{
	return MON_INSTANCES;
}

/* Returns statistics related to the given monitor instance.
 *
 * The function's arguments ifindex, rate and mac are filled with the
 * ifindex of the net_device being monitored, the current rate and the
 * mac address of the last pkt seen in that net_device respectively
 */
void monitor_get_stats(int instance, int *ifindex, int *rate, char *mac)
{
	spin_lock_bh(&monitors[instance].lock);
	*rate = __monitor_get_rate(&monitors[instance]);
	*ifindex = monitors[instance].ifindex;
	memcpy(mac, monitors[instance].mac, ETH_ADDR_LEN);
    if (*ifindex != 0) {
        printk(KERN_ALERT "RK: monitor_get_stats! %d\n", *ifindex);
        print_monitor(&monitors[instance]);
    }
	spin_unlock_bh(&monitors[instance].lock);


}

/* Set the threshold for a given net_device ifindex. If there is no
 * monitor instance associated with this net_device, this function
 * will try to allocate a new monitor instance for the given
 * net_device ifindex.  */
int monitor_set(int ifindex, u32 limit, int is_tnic)
{
    printk(KERN_ALERT "RK: monitor_set! %d\n", ifindex);
	int rc;

	spin_lock_bh(&monitor_cfg_lock);
	rc = __monitor_set(ifindex, limit, is_tnic);
	spin_unlock_bh(&monitor_cfg_lock);

	return rc;
}

int monitor_unset(int ifindex)
{
    printk(KERN_ALERT "RK: monitor_unset! %d\n", ifindex);
	int rc;

	spin_lock_bh(&monitor_cfg_lock);
	rc = __monitor_unset(ifindex);
	spin_unlock_bh(&monitor_cfg_lock);

	return rc;
}
