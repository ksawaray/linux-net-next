/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_DUPNAT_IPV4_H_
#define _NF_DUPNAT_IPV4_H_

#include <net/netfilter/ipv4/nf_dup_ipv4.h>

/**
 * struct nf_dupnat_info - dupnat target information
 * @gw: gateway IPv4 address
 * @new_dst: new destination IPv4 address
 * @port: destination port number (0 = don't change port)
 * @flags: dupnat flags
 * @oif: output interface index
 */
struct nf_dupnat_info {
	struct in_addr gw;
	struct in_addr new_dst;
	__be16 port;
	u32 flags;
	int oif;
};

void nf_dupnat_ipv4(struct net *net, struct sk_buff *skb, unsigned int hooknum,
		    const struct nf_dupnat_info *info);

#endif /* _NF_DUPNAT_IPV4_H_ */

