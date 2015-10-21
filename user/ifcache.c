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

#include <arpa/inet.h>		/* hton*() */
#include <netpacket/packet.h>   /* for sockaddr_ll */
#include <net/if.h>		/* if_nametoindex */
#include <unistd.h>

#include "ifcache.h"

extern struct ifcache *ifcache_root;

/* Returns 0 on success, -1 on error */
static int ifcache_add(int ifindex, char *ifname)
{
	struct sockaddr_ll lladdr;
	struct ifcache *ifc = malloc(sizeof (struct ifcache));

	if (!ifc)
		return -1;

	strcpy(ifc->name, ifname);
	ifc->index = ifindex;

	/* We don't need sockets for tap interfaces  */ /*MARIO: WHY NOT??? */
	if (!(ifname[0] == 't' && ifname[1] == 'a' && ifname[2] == 'p')) {

		ifc->sock  = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_RK));
		if (ifc->sock < 0) {
			return -1;
		}

		bzero(&lladdr, sizeof(lladdr));
		lladdr.sll_family   = AF_PACKET;
		lladdr.sll_ifindex  = ifindex;
		if (bind(ifc->sock, (struct sockaddr *) &lladdr,
			 sizeof(struct sockaddr_ll)) < 0) {
			return -1;
		}
	}
	else
		ifc->sock = 0;

	HASH_ADD_INT(ifcache_root, index, ifc);
	return 0;
}

int   ifcache_name_to_index(char *ifname)
{
	struct ifcache *aux, *it;
	int ifindex;

	/* Linear search for now */
	HASH_ITER(hh, ifcache_root , it, aux) {
		if (strcmp(it->name, ifname) == 0) {
			return it->index;
		}
	}
	/* Not found in hash, try to resolve and add it */
	if ((ifindex = if_nametoindex(ifname)) > 0) {
		ifcache_add(ifindex, ifname);
		return ifindex;
	}
	return -1;
}

char *ifcache_index_to_name(int ifindex, char *ifname)
{
	struct ifcache *ifcp;

	HASH_FIND_INT(ifcache_root, &ifindex, ifcp);

	if (ifcp) {
		strcpy(ifname, ifcp->name);
		return ifname;
	}

	/* Not found in hash, add it */
	if (if_indextoname(ifindex,ifname)) {
		ifcache_add(ifindex, ifname);
		return ifname;
	}
	return NULL;
}

int   ifcache_index_to_sock(int ifindex)
{
	struct ifcache *ifcp;
	char ifname[IFNAMSIZ];

	HASH_FIND_INT(ifcache_root, &ifindex, ifcp);
	if (ifcp)
		return ifcp->sock;

	/* Not found in hash, add it */
	if (if_indextoname(ifindex, ifname)) {
		ifcache_add(ifindex, ifname);

		HASH_FIND_INT(ifcache_root, &ifindex, ifcp);
		if (ifcp)
			return ifcp->sock;
	}
	return -1;
}

int   ifcache_name_to_sock(char *ifname)
{
	struct ifcache *ifcp;
	int ifindex;

	if ((ifindex = ifcache_name_to_index(ifname)) > 0) {
		HASH_FIND_INT(ifcache_root, &ifindex, ifcp);
		if (ifcp)
			return ifcp->sock;
	}
	/* Don't try to add again, ifcache_name_to_index tried
	 * already */
	return -1;
}

/* Returns 0 on success, -1 on error */
int ifcache_del(int ifindex)
{
	struct ifcache *ifcp;

	HASH_FIND_INT(ifcache_root, &ifindex, ifcp);

	if (ifcp) {
		if (!(ifcp->name[0] == 't' &&
		      ifcp->name[1] == 'a' &&
		      ifcp->name[2] == 'p'))
			close(ifcp->sock);
		HASH_DEL(ifcache_root, ifcp);
		free(ifcp);
		return 0;
	}
	return -1;
}
