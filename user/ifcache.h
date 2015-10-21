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

#ifndef __IFCACHE_H_
#define __IFCACHE_H_

#include <net/if.h>
#include <uthash.h>

#include "tc.h"

struct ifcache
{
	int  index;
	int  sock;
	char name[IFNAMSIZ];
	UT_hash_handle hh;
};

int   ifcache_name_to_index(char *ifname);
char *ifcache_index_to_name(int ifindex, char *ifname);
int   ifcache_index_to_sock(int ifindex);
int   ifcache_name_to_sock(char *ifname);
int   ifcache_del(int ifindex);

#endif
