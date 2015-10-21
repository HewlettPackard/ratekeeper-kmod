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

#ifndef _RATEKEEPER_MESSAGING_KERNEL_H_
#define _RATEKEEPER_MESSAGING_KERNEL_H_

#include "messaging.h"
#include "monitor.h"

extern int rk_upcall_congestion(int ifindex, unsigned char *mac, u32 severity);
extern int rk_upcall_feedback(int ifindex, unsigned int severity);
int __init messaging_init(void);
void __exit messaging_exit(void);

#endif  /* _RATEKEEPER_MESSAGING_KERNEL_H_ */
