/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include <string.h>

#include "ip6.h"

#include "netdissect.h"
#include "addrtoname.h"
#include "extract.h"

static inline void
rt6_print_hex_string(netdissect_options *ndo, register const u_int8_t *p, int len)
{
	ND_PRINT((ndo, "["));
	while (len) {
		ND_PRINT((ndo, "%02x", *p));
		p++;
		len--;
	}
	ND_PRINT((ndo, "]"));
}

int
rt6_print(netdissect_options *ndo, register const u_char *bp, const u_char *bp2 _U_)
{
	register const struct ip6_rthdr *dp;
	register const struct ip6_rthdr0 *dp0;
	register const struct ip6_rthdr4 *dp4;
	register const u_char *ep;
	int i, len;
	register const struct in6_addr *addr;
	register const struct ip6_rthdr4_tlv *tlv;
	register const u_int8_t *p;
	register u_int16_t flags;

	dp = (const struct ip6_rthdr *)bp;
	len = dp->ip6r_len;

	/* 'ep' points to the end of available data. */
	ep = ndo->ndo_snapend;

	ND_TCHECK(dp->ip6r_segleft);

	ND_PRINT((ndo, "srcrt (len=%d(%d)", dp->ip6r_len,
		(dp->ip6r_len + 1) << 3));	/*)*/
	ND_PRINT((ndo, ", type=%d(%s)", dp->ip6r_type,
		dp->ip6r_type == IPV6_RTHDR_TYPE_0 ? "srcrt" :
		dp->ip6r_type == IPV6_RTHDR_TYPE_2 ? "mobile" :
		dp->ip6r_type == IPV6_RTHDR_TYPE_4 ? "v6sr" :
                "unknown"
		));
	ND_PRINT((ndo, ", segleft=%d", dp->ip6r_segleft));

	switch (dp->ip6r_type) {
	case IPV6_RTHDR_TYPE_0:
	case IPV6_RTHDR_TYPE_2:			/* Mobile IPv6 ID-20 */
		dp0 = (const struct ip6_rthdr0 *)dp;

		ND_TCHECK(dp0->ip6r0_reserved);
		if (dp0->ip6r0_reserved || ndo->ndo_vflag) {
			ND_PRINT((ndo, ", rsv=0x%0x",
			    EXTRACT_32BITS(&dp0->ip6r0_reserved)));
		}

		if (len % 2 == 1)
			goto trunc;
		len >>= 1;
		addr = &dp0->ip6r0_addr[0];
		for (i = 0; i < len; i++) {
			if ((const u_char *)(addr + 1) > ep)
				goto trunc;

			ND_PRINT((ndo, ", [%d]%s", i, ip6addr_string(ndo, addr)));
			addr++;
		}
		/*(*/
		ND_PRINT((ndo, ") "));
		return((dp0->ip6r0_len + 1) << 3);
		break;

	case IPV6_RTHDR_TYPE_4:			/* Segment Routing */
		dp4 = (struct ip6_rthdr4 *)dp;

		ND_TCHECK(dp4->ip6r4_firstseg);
		ND_PRINT((ndo, ", firstseg=%d", dp4->ip6r4_firstseg));

		ND_TCHECK(dp4->ip6r4_flags);
		flags = ntohs (dp4->ip6r4_flags);
		ND_PRINT((ndo, ", flags=%s%s%s%s%s",
				flags & IP6SR_CLEANUP   ? "C" : "",
				flags & IP6SR_PROTECTED ? "P" : "",
				flags & IP6SR_OAM       ? "O" : "",
				flags & IP6SR_ALERT     ? "A" : "",
				flags & IP6SR_HMAC      ? "H" : ""
		));
		if (ndo->ndo_vflag > 1)
			ND_PRINT((ndo, "(0x%04x)", flags));
		else if (!flags)
			ND_PRINT((ndo, "-", flags));

		ND_TCHECK(dp4->ip6r4_reserved);
		if (dp4->ip6r4_reserved || ndo->ndo_vflag > 1)
			ND_PRINT((ndo, ", rsv=0x%02x", dp4->ip6r4_reserved));

		if (len % 2 == 1)
			goto trunc;

		/* Segment list */
		ND_PRINT((ndo, ", segments={"));
		addr = &dp4->ip6r4_addr[0];
		for (i = 0; i <= dp4->ip6r4_firstseg; i++) {
			if ((u_char *)(addr + 1) > ep)
				goto trunc;

			ND_PRINT((ndo, "%s[%d%s]%s",
					i ? ", " : "",
					i,
					i == dp4->ip6r4_segleft ? "*" : "",
					ip6addr_string(ndo, addr)));
			addr++;
		}
		ND_PRINT((ndo, "}"));

		/* TLV section */
		len = (dp4->ip6r4_len + 1) << 3;
		p = (u_int8_t *)addr;
		i = p - (u_int8_t *)bp;
		while (i < len) {
			tlv = (struct ip6_rthdr4_tlv *)p;
			ND_TCHECK(tlv->ip6_rthdr4_tlv_len);

			switch (tlv->ip6_rthdr4_tlv_type) {
			case IP6SR_TLV_INGRESS_NODE:
				addr = (struct in6_addr *)(p + 4);
				ND_PRINT((ndo, ", ingress=%s",
					ip6addr_string(ndo, addr)));
				break;

			case IP6SR_TLV_EGRESS_NODE:
				addr = (struct in6_addr *)(p + 4);
				ND_PRINT((ndo, ", egress=%s",
					ip6addr_string(ndo, addr)));
				break;

			case IP6SR_TLV_OPAQUE_CONTAINER:
				ND_PRINT((ndo, ", opaque=%dbytes",
					tlv->ip6_rthdr4_tlv_len));
				if (ndo->ndo_vflag > 1)
					rt6_print_hex_string(ndo,
						p + 4,
						tlv->ip6_rthdr4_tlv_len - 2);
				break;

			case IP6SR_TLV_PADDING:
				ND_PRINT((ndo, ", padding=%dbytes",
					tlv->ip6_rthdr4_tlv_len));
				if (ndo->ndo_vflag > 1)
					rt6_print_hex_string(ndo,
						p + 2,
						tlv->ip6_rthdr4_tlv_len);
				break;

			case IP6SR_TLV_HMAC:
				ND_PRINT((ndo, ", hmac=%dbytes",
					tlv->ip6_rthdr4_tlv_len));
				if (ndo->ndo_vflag > 1) {
					ND_PRINT((ndo, " {key="));
					rt6_print_hex_string(ndo,
						p + 4, 4);
					ND_PRINT((ndo, ", hmac="));
					rt6_print_hex_string(ndo,
						p + 8, 32);
					ND_PRINT((ndo, "}"));
				}
				break;

			default:
				ND_PRINT((ndo, ", unknown=%dbytes",
					tlv->ip6_rthdr4_tlv_len));
				break;
			}

			p += tlv->ip6_rthdr4_tlv_len + 2;
			i += tlv->ip6_rthdr4_tlv_len + 2;
		}

		if (i > len)
			goto trunc;

		/*(*/
		ND_PRINT((ndo, ") "));
		return((dp4->ip6r4_len + 1) << 3);
		break;

	default:
		goto trunc;
		break;
	}

 trunc:
	ND_PRINT((ndo, "[|srcrt]"));
	return -1;
}
