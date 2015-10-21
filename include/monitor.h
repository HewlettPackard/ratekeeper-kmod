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

#ifndef _RATEKEEPER_MONITOR_H__
#define _RATEKEEPER_MONITOR_H__

/* Monitor handling return codes */
#define MON_UPCALL         0x0 /* Packet intercepted and sent to userspace */
#define MON_UNAVAILABLE    0x1 /* All monitors are in use */
#define MON_UPDATED        0x2 /* Monitor updated properly */
#define MON_FREED          0x4 /* Monitor released successfully */
#define MON_NOT_FOUND      0x8 /* No monitor instance found for given attr */
#define MON_SET           0x10 /* Monitor set up */
#define MON_UNSET         0x20 /* Monitor set up */
#define MON_THRESHOLD     0x40 /* Monitor has its own threshold */
#define MON_ERROR         0x80

#define MON_INSTANCES        129 /* Max number of instances 
                                    We need 2 instances per VM plus one 
                                    for the accumulator
                                    thus 129 can support up to 64 VMs */

#define ETH_ADDR_LEN         6

int monitor_set(int ifindex, u32 limit, int is_vnic);
int monitor_unset(int ifindex);
int monitor_get_instances(void);
void monitor_get_stats(int instance, int *ifindex, int *rate, char *mac);
int __init monitor_init(uint32_t RK_INTERVAL, uint32_t RK_THRESHOLD);
void __exit monitor_exit(void);

#endif /* _RATEKEEPER_MONITOR_H__ */
