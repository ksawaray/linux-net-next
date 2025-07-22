// SPDX-License-Identifier: GPL-2.0-only
/*
 * IPv4 packet duplication with destination NAT and port modification
 * 
 * Based on nf_dup_ipv4.c but with enhanced functionality to:
 * - Duplicate packets
 * - Change destination IP address in duplicated packet
 * - Change destination port in duplicated packet
 * - Route duplicated packet to new destination
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/netfilter/ipv4/nf_dup_ipv4.h>
#include <net/netfilter/ipv4/nf_dupnat_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/checksum.h>
#include <net/inet_dscp.h>
#include <uapi/linux/netfilter/nf_tables.h>

static struct rtable *nf_dupnat_ipv4_route(struct net *net, struct sk_buff *skb,
					    const struct nf_dupnat_info *info)
{
	struct iphdr *iph = ip_hdr(skb);
	struct flowi4 fl4;
	struct rtable *rt;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = info->new_dst.s_addr;
	fl4.saddr = iph->saddr;
	fl4.flowi4_tos = inet_dscp_to_dsfield(ip4h_dscp(iph));
	fl4.flowi4_oif = info->oif;
	fl4.flowi4_proto = iph->protocol;
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;

	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return NULL;

	return rt;
}

static bool nf_dupnat_change_port(struct sk_buff *skb, __be16 new_port)
{
	struct iphdr *iph = ip_hdr(skb);
	__sum16 *check;
	__be16 oldport;

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph;
		
		if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct tcphdr)))
			return false;
			
		tcph = (struct tcphdr *)(iph + 1);
		oldport = tcph->dest;
		tcph->dest = new_port;
		check = &tcph->check;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph;
		
		if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct udphdr)))
			return false;
			
		udph = (struct udphdr *)(iph + 1);
		oldport = udph->dest;
		udph->dest = new_port;
		check = &udph->check;
		break;
	}
	default:
		return true; /* No port to change */
	}

	/* Update checksum */
	inet_proto_csum_replace2(check, skb, oldport, new_port, false);
	
	return true;
}

static bool nf_dupnat_change_dst(struct sk_buff *skb, __be32 new_dst)
{
	struct iphdr *iph = ip_hdr(skb);
	__be32 olddst = iph->daddr;

	/* Change destination IP */
	csum_replace4(&iph->check, olddst, new_dst);
	iph->daddr = new_dst;

	/* Update layer 4 checksum */
	switch (iph->protocol) {
	case IPPROTO_TCP: {
		struct tcphdr *tcph;
		
		if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct tcphdr)))
			return false;
			
		tcph = (struct tcphdr *)(iph + 1);
		inet_proto_csum_replace4(&tcph->check, skb, olddst, new_dst, true);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph;
		
		if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct udphdr)))
			return false;
			
		udph = (struct udphdr *)(iph + 1);
		if (udph->check != 0)
			inet_proto_csum_replace4(&udph->check, skb, olddst, new_dst, true);
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmph;
		
		if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct icmphdr)))
			return false;
			
		icmph = (struct icmphdr *)(iph + 1);
		inet_proto_csum_replace4(&icmph->checksum, skb, olddst, new_dst, true);
		break;
	}
	}

	return true;
}

void nf_dupnat_ipv4(struct net *net, struct sk_buff *skb, unsigned int hooknum,
		    const struct nf_dupnat_info *info)
{
	struct sk_buff *nskb;
	struct rtable *rt;
	struct iphdr *iph;
	
	local_bh_disable();
	
	/* Check for infinite loops */
	if (current->in_nf_duplicate)
		goto out;
	
	/* Duplicate the packet */
	nskb = pskb_copy(skb, GFP_ATOMIC);
	if (!nskb) {
		pr_debug("nf_dupnat_ipv4: failed to duplicate packet\n");
		goto out;
	}

	/* Check if we have enough data */
	if (!pskb_may_pull(nskb, sizeof(struct iphdr))) {
		pr_debug("nf_dupnat_ipv4: insufficient packet data\n");
		kfree_skb(nskb);
		goto out;
	}

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	/* Set connection tracking to untracked for duplicated packet */
	nf_reset_ct(nskb);
	nf_ct_set(nskb, NULL, IP_CT_UNTRACKED);
#endif

	/* Change destination IP address */
	if (!nf_dupnat_change_dst(nskb, info->new_dst.s_addr)) {
		pr_debug("nf_dupnat_ipv4: failed to change destination\n");
		kfree_skb(nskb);
		goto out;
	}

	/* Change destination port if specified */
	if (info->port != 0 && (info->flags & NFT_DUPNAT_F_CHANGE_PORT)) {
		if (!nf_dupnat_change_port(nskb, info->port)) {
			pr_debug("nf_dupnat_ipv4: failed to change port\n");
			kfree_skb(nskb);
			goto out;
		}
	}

	/* Set up routing */
	rt = nf_dupnat_ipv4_route(net, nskb, info);
	if (!rt) {
		pr_debug("nf_dupnat_ipv4: failed to find route\n");
		kfree_skb(nskb);
		goto out;
	}

	/* Set destination and update packet info */
	skb_dst_drop(nskb);
	skb_dst_set(nskb, &rt->dst);
	nskb->dev = rt->dst.dev;
	nskb->protocol = htons(ETH_P_IP);

	/*
	 * Adjust TTL and set DF flag for loop mitigation
	 * IP header checksum will be recalculated at ip_local_out.
	 */
	iph = ip_hdr(nskb);
	iph->frag_off |= htons(IP_DF);
	if (hooknum == NF_INET_PRE_ROUTING ||
	    hooknum == NF_INET_LOCAL_IN)
		--iph->ttl;

	/* Send the duplicated and modified packet */
	current->in_nf_duplicate = true;
	switch (hooknum) {
	case NF_INET_PRE_ROUTING:
	case NF_INET_LOCAL_IN:
	case NF_INET_FORWARD:
	case NF_INET_LOCAL_OUT:
		ip_local_out(net, nskb->sk, nskb);
		break;
	case NF_INET_POST_ROUTING:
		ip_output(net, nskb->sk, nskb);
		break;
	default:
		kfree_skb(nskb);
		break;
	}
	current->in_nf_duplicate = false;

out:
	local_bh_enable();
}
EXPORT_SYMBOL_GPL(nf_dupnat_ipv4);

MODULE_AUTHOR("Linux Kernel netfilter team");
MODULE_DESCRIPTION("nf_dupnat_ipv4: Duplicate IPv4 packets with destination NAT and port modification");
MODULE_LICENSE("GPL");

