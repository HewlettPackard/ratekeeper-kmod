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

#ifndef __TC_H_
#define __TC_H_

#include "../include/messaging_user.h"
#include "rkvif.h"
struct rkvnic;
struct rktnic;

#define ETH_ALEN       6

void tc_setup();
inline void tc_default_options(struct tc_options *tco, int max);
int tc_set(struct rkvnic *vnic, int link_max);
int get_nic_speed(char *nic);
int get_nic_hwaddr(char *nic, char *mac);
void tc_set_rate(struct rkvnic *vnic);
void tc_update_ifbs(int link_max, struct tc_options *vnic_tco, struct tc_options *tnic_tco);
void tc_update_tnic(struct rktnic *tnic, int link_max);

#endif /* __TC_H_ */
