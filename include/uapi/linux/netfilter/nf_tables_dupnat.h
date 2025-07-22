/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _NF_TABLES_DUPNAT_H_
#define _NF_TABLES_DUPNAT_H_

/**
 * enum nft_dupnat_attributes - dupnat expression netlink attributes
 *
 * @NFTA_DUPNAT_UNSPEC: unspecified attribute
 * @NFTA_DUPNAT_ADDR: gateway IPv4 address (NLA_U32: network byte order)
 * @NFTA_DUPNAT_PORT: destination port (NLA_U16: network byte order)
 * @NFTA_DUPNAT_DEV: output device name (NLA_STRING)
 * @NFTA_DUPNAT_FLAGS: dupnat flags (NLA_U32)
 * @NFTA_DUPNAT_SREG_ADDR: source register containing IPv4 address
 * @NFTA_DUPNAT_SREG_DEV: source register containing device index
 * @NFTA_DUPNAT_SREG_DST_ADDR: source register containing destination address
 */
enum nft_dupnat_attributes {
	NFTA_DUPNAT_UNSPEC,
	NFTA_DUPNAT_ADDR,
	NFTA_DUPNAT_PORT,
	NFTA_DUPNAT_DEV,
	NFTA_DUPNAT_FLAGS,
	NFTA_DUPNAT_SREG_ADDR,
	NFTA_DUPNAT_SREG_DEV,
	NFTA_DUPNAT_SREG_DST_ADDR,
	__NFTA_DUPNAT_MAX
};
#define NFTA_DUPNAT_MAX (__NFTA_DUPNAT_MAX - 1)

/**
 * enum nft_dupnat_flags - dupnat expression flags
 *
 * @NFT_DUPNAT_F_CHANGE_ROUTE: change route
 * @NFT_DUPNAT_F_CHANGE_PORT: change destination port
 */
enum nft_dupnat_flags {
	NFT_DUPNAT_F_CHANGE_ROUTE	= (1 << 0),
	NFT_DUPNAT_F_CHANGE_PORT	= (1 << 1),
};

#endif /* _NF_TABLES_DUPNAT_H_ */
