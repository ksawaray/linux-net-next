// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 dupnat extension for nftables
 * Based on nft_dup_ipv4.c
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/ipv4/nf_dupnat_ipv4.h>
#include <uapi/linux/netfilter/nf_tables_dupnat.h>

struct nft_dupnat_ipv4 {
	u8	sreg_addr;      /* Gateway address register */
	u8	sreg_dev;       /* Output interface register */
	u8	sreg_dst_addr;  /* New destination address register */
};

static void nft_dupnat_ipv4_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_dupnat_ipv4 *priv = nft_expr_priv(expr);
	struct nf_dupnat_info info;
	int oif = priv->sreg_dev ? regs->data[priv->sreg_dev] : -1;

	/* Set gateway and new destination */
	info.gw.s_addr = (__force __be32)regs->data[priv->sreg_addr];
	info.new_dst.s_addr = (__force __be32)regs->data[priv->sreg_dst_addr];
	info.oif = oif;
	info.port = 0;
	info.flags = 0;

	nf_dupnat_ipv4(nft_net(pkt), pkt->skb, nft_hook(pkt), &info);
}

static int nft_dupnat_ipv4_init(const struct nft_ctx *ctx,
				const struct nft_expr *expr,
				const struct nlattr * const tb[])
{
	struct nft_dupnat_ipv4 *priv = nft_expr_priv(expr);
	int err;

	if (tb[NFTA_DUPNAT_SREG_ADDR] == NULL)
		return -EINVAL;

	if (tb[NFTA_DUPNAT_SREG_DST_ADDR] == NULL)
		return -EINVAL;

	err = nft_parse_register_load(ctx, tb[NFTA_DUPNAT_SREG_ADDR], 
				      &priv->sreg_addr, sizeof(struct in_addr));
	if (err < 0)
		return err;

	err = nft_parse_register_load(ctx, tb[NFTA_DUPNAT_SREG_DST_ADDR],
				      &priv->sreg_dst_addr, sizeof(struct in_addr));
	if (err < 0)
		return err;

	if (tb[NFTA_DUPNAT_SREG_DEV])
		err = nft_parse_register_load(ctx, tb[NFTA_DUPNAT_SREG_DEV],
					      &priv->sreg_dev, sizeof(int));

	return err;
}

static int nft_dupnat_ipv4_dump(struct sk_buff *skb,
				const struct nft_expr *expr, bool reset)
{
	struct nft_dupnat_ipv4 *priv = nft_expr_priv(expr);

	if (nft_dump_register(skb, NFTA_DUPNAT_SREG_ADDR, priv->sreg_addr))
		goto nla_put_failure;
	if (nft_dump_register(skb, NFTA_DUPNAT_SREG_DST_ADDR, priv->sreg_dst_addr))
		goto nla_put_failure;
	if (priv->sreg_dev &&
	    nft_dump_register(skb, NFTA_DUPNAT_SREG_DEV, priv->sreg_dev))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static struct nft_expr_type nft_dupnat_ipv4_type;
static const struct nft_expr_ops nft_dupnat_ipv4_ops = {
	.type		= &nft_dupnat_ipv4_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_dupnat_ipv4)),
	.eval		= nft_dupnat_ipv4_eval,
	.init		= nft_dupnat_ipv4_init,
	.dump		= nft_dupnat_ipv4_dump,
	.reduce		= NFT_REDUCE_READONLY,
};

static const struct nla_policy nft_dupnat_ipv4_policy[NFTA_DUPNAT_MAX + 1] = {
	[NFTA_DUPNAT_SREG_ADDR]     = { .type = NLA_U32 },
	[NFTA_DUPNAT_SREG_DEV]      = { .type = NLA_U32 },
	[NFTA_DUPNAT_SREG_DST_ADDR] = { .type = NLA_U32 },
};

static struct nft_expr_type nft_dupnat_ipv4_type __read_mostly = {
	.family		= NFPROTO_IPV4,
	.name		= "dupnat",
	.ops		= &nft_dupnat_ipv4_ops,
	.policy		= nft_dupnat_ipv4_policy,
	.maxattr	= NFTA_DUPNAT_MAX,
	.owner		= THIS_MODULE,
};

static int __init nft_dupnat_ipv4_module_init(void)
{
	return nft_register_expr(&nft_dupnat_ipv4_type);
}

static void __exit nft_dupnat_ipv4_module_exit(void)
{
	nft_unregister_expr(&nft_dupnat_ipv4_type);
}

module_init(nft_dupnat_ipv4_module_init);
module_exit(nft_dupnat_ipv4_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dupnat extension");
MODULE_ALIAS_NFT_AF_EXPR(AF_INET, "dupnat");
MODULE_DESCRIPTION("IPv4 nftables packet duplication with destination NAT support");

