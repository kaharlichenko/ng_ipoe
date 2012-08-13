/*
 * ng_ipoe.h
 */

/*-
 * Copyright (c) 2012 Shtorm Corp, Ltd.
 * All rights reserved.
 * 
 * Subject to the following obligations and disclaimer of warranty, use and
 * redistribution of this software, in source or object code forms, with or
 * without modifications are expressly permitted by Whistle Communications;
 * provided, however, that:
 * 1. Any and all reproductions of the source or object code must include the
 *    copyright notice above and the following disclaimer of warranties; and
 * 2. No rights are granted, in any manner or form, to use Whistle
 *    Communications, Inc. trademarks, including the mark "WHISTLE
 *    COMMUNICATIONS" on advertising, endorsements, or otherwise except as
 *    such appears in the above copyright notice or in the software.
 * 
 * THIS SOFTWARE IS BEING PROVIDED BY WHISTLE COMMUNICATIONS "AS IS", AND
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, WHISTLE COMMUNICATIONS MAKES NO
 * REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, REGARDING THIS SOFTWARE,
 * INCLUDING WITHOUT LIMITATION, ANY AND ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * WHISTLE COMMUNICATIONS DOES NOT WARRANT, GUARANTEE, OR MAKE ANY
 * REPRESENTATIONS REGARDING THE USE OF, OR THE RESULTS OF THE USE OF THIS
 * SOFTWARE IN TERMS OF ITS CORRECTNESS, ACCURACY, RELIABILITY OR OTHERWISE.
 * IN NO EVENT SHALL WHISTLE COMMUNICATIONS BE LIABLE FOR ANY DAMAGES
 * RESULTING FROM OR ARISING OUT OF ANY USE OF THIS SOFTWARE, INCLUDING
 * WITHOUT LIMITATION, ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * PUNITIVE, OR CONSEQUENTIAL DAMAGES, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES, LOSS OF USE, DATA OR PROFITS, HOWEVER CAUSED AND UNDER ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF WHISTLE COMMUNICATIONS IS ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Ihor Kaharlichenko <madkinder@gmail.com>
 *
 */

/* TODO: Check the license block */

#ifndef _NETGRAPH_NG_IPOE_H_
#define _NETGRAPH_NG_IPOE_H_

#define NG_IPOE_NODE_TYPE	"ipoe"

#define NGM_IPOE_COOKIE		1336571564

/* Hook names */
#define NG_IPOE_HOOK_NOMATCH	"nomatch"
#define NG_IPOE_HOOK_DOWNSTREAM	"downstream"
#define NG_IPOE_HOOK_SERVICE	"service"

/* Netgraph commands. */
enum {
	NGM_IPOE_ADD_FILTER = 1,
	NGM_IPOE_DEL_FILTER,
	NGM_IPOE_ADD_ARP,
	NGM_IPOE_DEL_ARP,
	NGM_IPOE_GET_ENADDR,
	NGM_IPOE_SET_ENADDR,
	NGM_IPOE_GET_CONFIG
};

/* For NGM_IPOE_ADD_FILTER control message. */
struct ng_ipoe_filter {
	char		hook[NG_HOOKSIZ];
	u_int16_t	outer_vlan;
	u_int16_t	inner_vlan;
};	

/* Keep this in sync with the above structure definition.  */
#define	NG_IPOE_FILTER_FIELDS	{				\
	{ "hook",	&ng_parse_hookbuf_type  },		\
	{ "outer_vlan",	&ng_parse_uint16_type   },		\
	{ "inner_vlan",	&ng_parse_uint16_type   },		\
	{ NULL }						\
}

/* For NGM_IPOE_ADD_ARP and NGM_IPOE_DEL_ARP control messages. */
struct ng_ipoe_arp {
	char		hook[NG_HOOKSIZ];
	struct	in_addr ip;
	u_char		mac[ETHER_ADDR_LEN];
};

/* Keep this in sync with the above structure definition.  */
#define	NG_IPOE_ARP_FIELDS	{				\
	{ "hook",	&ng_parse_hookbuf_type  },		\
	{ "ip",		&ng_parse_ipaddr_type   },		\
	{ "mac",	&ng_parse_enaddr_type   },		\
	{ NULL }						\
}

/* For NGM_IPOE_GET_CONFIG control message. */
struct ng_ipoe_arp_entry {
	struct	in_addr ip;
	u_char		mac[ETHER_ADDR_LEN];
};

/* Keep this in sync with the above structure definition.  */
#define	NG_IPOE_ARP_ENTRY_FIELDS	{				\
	{ "ip",		&ng_parse_ipaddr_type   },		\
	{ "mac",	&ng_parse_enaddr_type   },		\
	{ NULL }						\
}


/* Structure returned by NGM_IPOE_GET_CONFIG. */
struct ng_ipoe_config {
	u_int16_t		outer_vlan;
	u_int16_t		inner_vlan;
	u_int32_t		arp_len;
	struct ng_ipoe_arp_entry arp[];
};

/* Keep this in sync with the above structure definition. */
#define	NG_IPOE_CONFIG_FIELDS	{				\
	{ "outer_vlan",	&ng_parse_uint16_type },		\
	{ "inner_vlan",	&ng_parse_uint16_type },		\
	{ "arp_len",	&ng_parse_uint32_type },		\
	{ "arp",	&ng_ipoe_config_array_type },		\
	{ NULL }						\
}

#endif /* _NETGRAPH_NG_IPOE_H_ */
