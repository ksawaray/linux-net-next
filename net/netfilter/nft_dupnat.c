// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015 Pablo Neira Ayuso <pablo@netfilter.org>
 * Enhanced dupnat with port modification support
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/ipv4/nf_dupnat_ipv4.h>
#include <net/netfilter/ipv6/nf_dup_ipv6.h>
#include <uapi/linux/netfilter/nf_tables_dupnat.h>

struct nft_dupnat {
	u8		sreg_addr;
	u8		sreg_port;
	u8		sreg_dev;
	u32		flags;
};

static void nft_dupnat_ipv4_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_dupnat *priv = nft_expr_priv(expr);
	struct nf_dupnat_info info;
	struct net_device *dev;
	int oif = 0;

	/* Get destination address */
	info.new_dst.s_addr = (__force __be32)
		regs->data[priv->sreg_addr];

	/* Get port if specified */
	if (priv->sreg_port != NFT_REG_UNSPEC) {
		info.port = (__force __be16)
			regs->data[priv->sreg_port];
		info.flags |= NFT_DUPNAT_F_CHANGE_PORT;
	} else {
		info.port = 0;
	}

	/* Get output device if specified */
	if (priv->sreg_dev != NFT_REG_UNSPEC) {
		dev = *((struct net_device **)
			&regs->data[priv->sreg_dev]);
		if (dev != NULL)
			oif = dev->ifindex;
	}

	info.oif = oif;
	info.gw = info.new_dst; /* Use new destination as gateway */
	info.flags = priv->flags;

	nf_dupnat_ipv4(nft_net(pkt), pkt->skb, nft_hook(pkt), &info);
}

static void nft_dupnat_ipv6_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_dupnat *priv = nft_expr_priv(expr);
	struct in6_addr *gw = (struct in6_addr *)&regs->data[priv->sreg_addr];
	int oif = 0;

	if (priv->sreg_dev != NFT_REG_UNSPEC) {
		struct net_device *dev = *((struct net_device **)
			&regs->data[priv->sreg_dev]);
		if (dev != NULL)
			oif = dev->ifindex;
	}

	/* IPv6 dupnat not implemented yet, fall back to regular dup */
	nf_dup_ipv6(nft_net(pkt), pkt->skb, nft_hook(pkt), gw, oif);
}

static void nft_dupnat_eval(const struct nft_expr *expr,
			    struct nft_regs *regs,
			    const struct nft_pktinfo *pkt)
{
	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		nft_dupnat_ipv4_eval(expr, regs, pkt);
		break;
	case NFPROTO_IPV6:
		nft_dupnat_ipv6_eval(expr, regs, pkt);
		break;
	}
}

static const struct nla_policy nft_dupnat_policy[NFTA_DUPNAT_MAX + 1] = {
	[NFTA_DUPNAT_ADDR]	= { .type = NLA_U32 },
	[NFTA_DUPNAT_PORT]	= { .type = NLA_U16 },
	[NFTA_DUPNAT_DEV]	= { .type = NLA_STRING,
				    .len = IFNAMSIZ - 1 },
	[NFTA_DUPNAT_FLAGS]	= { .type = NLA_U32 },
};

static int nft_dupnat_init(const struct nft_ctx *ctx,
			   const struct nft_expr *expr,
			   const struct nlattr * const tb[])
{
	struct nft_dupnat *priv = nft_expr_priv(expr);
	unsigned int len;
	int err;

	if (tb[NFTA_DUPNAT_ADDR] == NULL)
		return -EINVAL;

	priv->sreg_addr = nft_parse_register(tb[NFTA_DUPNAT_ADDR]);
	err = nft_validate_register_load(priv->sreg_addr, sizeof(struct in_addr));
	if (err < 0)
		return err;

	if (tb[NFTA_DUPNAT_PORT] != NULL) {
		priv->sreg_port = nft_parse_register(tb[NFTA_DUPNAT_PORT]);
		err = nft_validate_register_load(priv->sreg_port, sizeof(u16));
		if (err < 0)
			return err;
	} else {
		priv->sreg_port = NFT_REG_UNSPEC;
	}

	if (tb[NFTA_DUPNAT_DEV] != NULL) {
		len = nla_len(tb[NFTA_DUPNAT_DEV]);
		priv->sreg_dev = nft_parse_register(tb[NFTA_DUPNAT_DEV]);
		err = nft_validate_register_load(priv->sreg_dev,
						 sizeof(struct net_device *));
		if (err < 0)
			return err;
	} else {
		priv->sreg_dev = NFT_REG_UNSPEC;
	}

	if (tb[NFTA_DUPNAT_FLAGS] != NULL) {
		priv->flags = ntohl(nla_get_be32(tb[NFTA_DUPNAT_FLAGS]));
		if (priv->flags & ~(NFT_DUPNAT_F_CHANGE_ROUTE | 
				    NFT_DUPNAT_F_CHANGE_PORT))
			return -EOPNOTSUPP;
	}

	return 0;
}

static int nft_dupnat_dump(struct sk_buff *skb, const struct nft_expr *expr)
{
	struct nft_dupnat *priv = nft_expr_priv(expr);

	if (nft_dump_register(skb, NFTA_DUPNAT_ADDR, priv->sreg_addr))
		goto nla_put_failure;

	if (priv->sreg_port != NFT_REG_UNSPEC &&
	    nft_dump_register(skb, NFTA_DUPNAT_PORT, priv->sreg_port))
		goto nla_put_failure;

	if (priv->sreg_dev != NFT_REG_UNSPEC &&
	    nft_dump_register(skb, NFTA_DUPNAT_DEV, priv->sreg_dev))
		goto nla_put_failure;

	if (priv->flags &&
	    nla_put_be32(skb, NFTA_DUPNAT_FLAGS, htonl(priv->flags)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static struct nft_expr_type nft_dupnat_type;
static const struct nft_expr_ops nft_dupnat_ipv4_ops = {
	.type		= &nft_dupnat_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_dupnat)),
	.eval		= nft_dupnat_eval,
	.init		= nft_dupnat_init,
	.dump		= nft_dupnat_dump,
};

static const struct nft_expr_ops nft_dupnat_ipv6_ops = {
	.type		= &nft_dupnat_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_dupnat)),
	.eval		= nft_dupnat_eval,
	.init		= nft_dupnat_init,
	.dump		= nft_dupnat_dump,
};

static const struct nft_expr_ops *
nft_dupnat_select_ops(const struct nft_ctx *ctx,
		      const struct nlattr * const tb[])
{
	if (ctx->family == NFPROTO_IPV4)
		return &nft_dupnat_ipv4_ops;
	else if (ctx->family == NFPROTO_IPV6)
		return &nft_dupnat_ipv6_ops;

	return ERR_PTR(-EOPNOTSUPP);
}

static struct nft_expr_type nft_dupnat_type __read_mostly = {
	.name		= "dupnat",
	.select_ops	= nft_dupnat_select_ops,
	.policy		= nft_dupnat_policy,
	.maxattr	= NFTA_DUPNAT_MAX,
	.owner		= THIS_MODULE,
};

static int __init nft_dupnat_module_init(void)
{
	return nft_register_expr(&nft_dupnat_type);
}

static void __exit nft_dupnat_module_exit(void)
{
	nft_unregister_expr(&nft_dupnat_type);
}

module_init(nft_dupnat_module_init);
module_exit(nft_dupnat_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel netfilter team");
MODULE_DESCRIPTION("nftables dupnat expression with port modification support");
MODULE_ALIAS_NFT_EXPR("dupnat");

