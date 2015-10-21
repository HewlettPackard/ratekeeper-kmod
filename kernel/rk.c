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

#define RK_VERSION "0.1"

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/if_bridge.h>

#include "../include/monitor.h"
#include "../include/messaging_kernel.h"

/* Module parameters */
uint RK_INTERVAL __read_mostly = 1024;
module_param    (RK_INTERVAL, uint, 0640);
MODULE_PARM_DESC(RK_INTERVAL,
                 "RK monitoring interval (in us), default "
                 "1024us ~= 1ms. For improved accuracy, "
                 "specify interavals in powers of 2");
/* Altough the minimum time interval the monitor can keep track of is
 * 1 psched tick (see <net/pkt_sched.h> for more info), where 1 psched
 * tick is equivalent to 64ns, the interval should be given in us,
 * because if the interval is too short, we are not able to keep track
 * of slow rates accurately.
 */

uint RK_THRESHOLD __read_mostly = 62;
module_param    (RK_THRESHOLD, uint, 0640);
MODULE_PARM_DESC(RK_THRESHOLD,
                 "RK threshold to generate notifications (in bytes/us), "
                 "default 62 ~= 500mbit/s");
/* The rate should be given in bytes/us. The implementation uses this
 * unit instead of bytes/ns because the smaller the time interval for
 * measuring rates, the greater the loss of representation due to
 * underflows. So, the minimum rate that a monitor can handle is
 * 10mbps, which would be ~=1.25 bytes/us.
 */
static int __init rk_init(void)
{
	int stat;

	stat =
		monitor_init(RK_INTERVAL, RK_THRESHOLD) |
		messaging_init();;
	printk(KERN_ALERT "Ratekeeper version "RK_VERSION" LOADED: RK_INTERVAL=%u RK_THRESHOLD=%u\n",
	       RK_INTERVAL, RK_THRESHOLD);

	return stat;
}

static void __exit rk_deinit(void)
{
	printk(KERN_ALERT "UNLOADING Ratekeeper\n");
	monitor_exit();
	messaging_exit();
}

module_init(rk_init);
module_exit(rk_deinit)
MODULE_LICENSE("GPL");
MODULE_VERSION(RK_VERSION);
