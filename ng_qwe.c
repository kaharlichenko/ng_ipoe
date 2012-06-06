/*
 * ng_qwe.c
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/socket.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_vlan_var.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/netgraph.h>

#include "ng_qwe.h"

#define IS_DHCP(udp) \
( \
(((udp)->uh_sport == htons(67)) && ((udp)->uh_dport == htons(68))) || \
(((udp)->uh_sport == htons(68)) && ((udp)->uh_dport == htons(67))) \
)

#define IS_INVALID_VLAN(vlan) (((vlan) < 1) || ((vlan) > 4095))

#define IS_FILTER_IN_SERVICE(f) \
	(((f)->outer_vlan != 0) && ((f)->inner_vlan != 0))

#define IS_HOOK_IN_SERVICE(hook) \
	IS_FILTER_IN_SERVICE(((struct filter *)NG_HOOK_PRIVATE(hook)))

#define ARP_ETHER_TO_IP4_HDR_LEN (sizeof(struct arphdr) + \
    2 * (ETHER_ADDR_LEN + sizeof(struct in_addr)))

/*
 * This section contains the netgraph method declarations for the
 * qwe node. These methods define the netgraph 'type'.
 */

static ng_constructor_t	ng_qwe_constructor;
static ng_shutdown_t	ng_qwe_shutdown;
static ng_rcvmsg_t	ng_qwe_rcvmsg;
static ng_newhook_t	ng_qwe_newhook;
static ng_rcvdata_t	ng_qwe_rcvdata;
static ng_disconnect_t	ng_qwe_disconnect;

/* Parse type for struct ng_qwe_filter. */
static const struct ng_parse_struct_field ng_qwe_filter_fields[] =
	NG_QWE_FILTER_FIELDS;
static const struct ng_parse_type ng_qwe_filter_type = {
	&ng_parse_struct_type,
	&ng_qwe_filter_fields
};

/* Parse type for struct ng_qwe_arp_entry. */
static const struct ng_parse_struct_field ng_qwe_arp_entry_fields[] =
	NG_QWE_ARP_ENTRY_FIELDS;
static const struct ng_parse_type ng_qwe_arp_entry_type = {
	&ng_parse_struct_type,
	&ng_qwe_arp_entry_fields
};

/* Parse type for struct ng_qwe_config. */
static int
ng_qwe_get_arp_length(const struct ng_parse_type *type,
    const u_char *start, const u_char *buf)
{
	const struct ng_qwe_config *const config =
	    (const struct ng_qwe_config *)(buf - 2 * sizeof(u_int16_t) -
	    sizeof(u_int32_t));

	return config->arp_len;
}

static const struct ng_parse_array_info ng_qwe_arp_array_info = {
	&ng_qwe_arp_entry_type,
	ng_qwe_get_arp_length
};
static const struct ng_parse_type ng_qwe_config_array_type = {
	&ng_parse_array_type,
	&ng_qwe_arp_array_info
};

static const struct ng_parse_struct_field ng_qwe_config_fields[] =
	NG_QWE_CONFIG_FIELDS;
static const struct ng_parse_type ng_qwe_config_type = {
	&ng_parse_struct_type,
	&ng_qwe_config_fields
};

/* Parse type for struct ng_qwe_arp. */
static const struct ng_parse_struct_field ng_qwe_arp_fields[] =
	NG_QWE_ARP_FIELDS;
static const struct ng_parse_type ng_qwe_arp_type = {
	&ng_parse_struct_type,
	&ng_qwe_arp_fields
};

static const struct ng_cmdlist ng_qwe_cmdlist[] = {
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_ADD_FILTER,
	  "addfilter",
	  &ng_qwe_filter_type,
	  NULL
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_DEL_FILTER,
	  "delfilter",
	  &ng_parse_hookbuf_type,
	  NULL
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_ADD_ARP,
	  "addarp",
	  &ng_qwe_arp_type,
	  NULL
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_DEL_ARP,
	  "delarp",
	  &ng_qwe_arp_type,
	  NULL
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_GET_ENADDR,
	  "getenaddr",
	  NULL,
	  &ng_parse_enaddr_type
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_SET_ENADDR,
	  "setenaddr",
	  &ng_parse_enaddr_type,
	  NULL
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_GET_CONFIG,
	  "getconfig",
	  &ng_parse_hookbuf_type,
	  &ng_qwe_config_type
	},
	{ 0 }
};

/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_QWE_NODE_TYPE,
	.constructor =	ng_qwe_constructor,
	.rcvmsg =	ng_qwe_rcvmsg,
	.shutdown =	ng_qwe_shutdown,
	.newhook =	ng_qwe_newhook,
	.rcvdata =	ng_qwe_rcvdata,
	.disconnect =	ng_qwe_disconnect,
	.cmdlist =	ng_qwe_cmdlist,
};
NETGRAPH_INIT(qwe, &typestruct);


/* Information we store for each node */
struct arp_entry {
	LIST_ENTRY(arp_entry) next;
	struct in_addr	ip;
	u_char		mac[ETHER_ADDR_LEN];
};
LIST_HEAD(arphead, arp_entry);

struct filter {
	LIST_ENTRY(filter) next;
	hook_p		hook;
	u_int16_t	outer_vlan;
	u_int16_t	inner_vlan;
	u_int32_t	arp_len;
	struct arphead	arp_table;
};

LIST_HEAD(filterhead, filter);

struct ng_qwe_private {
	hook_p  	nomatch;
	hook_p  	downstream;
	hook_p  	service;
	struct filterhead filters;
	u_char		mac[ETHER_ADDR_LEN];
	node_p		node;		/* back pointer to node */
};
typedef struct ng_qwe_private *private_p;

/* VLAN related functions. */
static struct filter *
ng_qwe_find_entry(private_p priv,
    u_int16_t outer_vlan, u_int16_t inner_vlan)
{
	struct filterhead	*head = &priv->filters;
	struct filter		*f;

	LIST_FOREACH(f, head, next)
		if (f->outer_vlan == outer_vlan &&
		    f->inner_vlan == inner_vlan)
			return (f);

	return (NULL);
}

static void
ng_qwe_add_filter(hook_p hook,
    u_int16_t outer_vlan, u_int16_t inner_vlan)
{
	private_p	node_priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct filter	*f = NG_HOOK_PRIVATE(hook);

	f->outer_vlan = outer_vlan;
	f->inner_vlan = inner_vlan;

	/* Register filter in a filter list. */
	LIST_INSERT_HEAD(&node_priv->filters, f, next);
}

static void
ng_qwe_del_filter(hook_p hook)
{
	struct filter *f = NG_HOOK_PRIVATE(hook);

	f->outer_vlan = 0;
	f->inner_vlan = 0;

	/* Register filter in a filter list. */
	LIST_REMOVE(f, next);
}

/* ARP related functions. */
static int
ng_qwe_is_valid_arp(const struct in_addr *ip, const u_char mac[ETHER_ADDR_LEN])
{
	struct in_addr	wildcard_ip = { 0 };
	const u_char	wildcard_mac[ETHER_ADDR_LEN] =
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	if (ETHER_IS_MULTICAST(mac))
		return (0);

	if (bcmp(ip, &wildcard_ip, sizeof(wildcard_ip)) == 0)
		return (0);

	if (bcmp(mac, wildcard_mac, ETHER_ADDR_LEN) == 0)
		return (0);

	return (1);
}

static struct arp_entry *
ng_qwe_find_arp(hook_p hook, const struct in_addr *ip,
    const u_char mac[ETHER_ADDR_LEN])
{
	struct filter *filter = NG_HOOK_PRIVATE(hook);
	struct arp_entry *arp;

	KASSERT(filter != NULL,
	    ("looking for an arp entry in a vlan without an attached filter"));

	LIST_FOREACH(arp, &filter->arp_table, next) {
		if (bcmp(ip, &arp->ip, sizeof(*ip)) != 0)
			continue;

		if ((mac != NULL) && (bcmp(mac, arp->mac, ETHER_ADDR_LEN) != 0))
			continue;

		return arp;
	}

	return (NULL);
}

static int
ng_qwe_add_arp(hook_p hook, const struct in_addr *ip,
    const u_char mac[ETHER_ADDR_LEN])
{
	struct arp_entry *arp = ng_qwe_find_arp(hook, ip, mac);
	struct filter *filter = NG_HOOK_PRIVATE(hook);
	KASSERT(filter != NULL,
	    ("attemp to add arp entry to a vlan without an attached filter"));

	if (arp != NULL)
		return (EEXIST);

	arp = malloc(sizeof(*arp), M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (arp == NULL)
		return (ENOMEM);

	bcopy(ip, &arp->ip, sizeof(*ip));
	bcopy(mac, arp->mac, ETHER_ADDR_LEN);

	/* Attach the arp entry to the filter. */
	LIST_INSERT_HEAD(&filter->arp_table, arp, next);
	++filter->arp_len;

	return (0);
}

static int
ng_qwe_del_arp(hook_p hook, const struct in_addr *ip,
    const u_char mac[ETHER_ADDR_LEN])
{
	struct arp_entry *arp = ng_qwe_find_arp(hook, ip, mac);
	struct filter *filter = NG_HOOK_PRIVATE(hook);

	if (arp == NULL)
		return (ENOENT);

	/* Remove the arp entry from the filter. */
	LIST_REMOVE(arp, next);
	free(arp, M_NETGRAPH);
	--filter->arp_len;

	return (0);
}

static struct mbuf *
ng_qwe_process_arp(struct mbuf * m, private_p priv)
{
	struct arphdr			*arp = NULL;
	struct ether_vlan_header	*evl = NULL;
	struct filter			*filter = NULL;
	struct arp_entry		*arp_entry = NULL;

	/*
	 * Since we provide IPv4 over Ethernet we care only about
	 * IPv4 to Ethernet address resolution.
	 */

	/* Make sure the packet is of appropriate size. */
	if (m->m_len < (sizeof(*evl) + ARP_ETHER_TO_IP4_HDR_LEN) &&
	    (m = m_pullup(m, sizeof(*evl) +
	    ARP_ETHER_TO_IP4_HDR_LEN)) == NULL) {
		return (NULL);
	}

	/*
	 * Make sure we got IPv4 to Ethernet address
	 * resolution requets packet.
	 */
	arp = (struct arphdr *)(mtod(m, char *) + sizeof(*evl));
	if (arp->ar_hrd != htons(ARPHRD_ETHER) ||
	    arp->ar_pro != htons(ETHERTYPE_IP) ||
	    arp->ar_hln != ETHER_ADDR_LEN ||
	    arp->ar_pln != sizeof(struct in_addr) ||
	    arp->ar_op  != htons(ARPOP_REQUEST)) {
		NG_FREE_M(m);
		return (NULL);
	}

	evl = mtod(m, struct ether_vlan_header *);
	/* Make sure we aren't getting spoofed. */
	if (bcmp(evl->evl_shost, ar_sha(arp), ETHER_ADDR_LEN) != 0) {
		/* XXX: Increment counter? */
		NG_FREE_M(m);
		return (NULL);
	}

	/* Drop gratuitous ARP. */
	if ((bcmp(ar_sha(arp), ar_tha(arp), sizeof(struct in_addr)) == 0) ||
	    (bcmp(ar_spa(arp), ar_tpa(arp), ETHER_ADDR_LEN) == 0)) {
		NG_FREE_M(m);
		return (NULL);
	}

	/* Check whether we handle this vlan at all. */
	filter = ng_qwe_find_entry(priv,
	    EVL_VLANOFTAG(m->m_pkthdr.ether_vtag),
	    EVL_VLANOFTAG(ntohs(evl->evl_tag)));

	if (filter == NULL) {
		/* This vlan is not served. */
		NG_FREE_M(m);
		return (NULL);
	}
	/*
	 * Target vlan found.
	 * Check against ARP table.
	 */
	arp_entry = ng_qwe_find_arp(filter->hook,
	    (struct in_addr *)ar_spa(arp), evl->evl_shost);

	if (arp_entry == NULL) {
		/* We don't serve those who aren't in our ARP table. */
		NG_FREE_M(m);
		return (NULL);
	}

	/* Construct an ARP reply reusing the same mbuf. */
	arp->ar_op = htons(ARPOP_REPLY);

	/*
	 * Set destination mac address to requester's one (Ethernet header).
	 * Set target mac address to requester's one (ARP body).
	 */
	bcopy(evl->evl_shost, evl->evl_dhost, ETHER_ADDR_LEN);
	bcopy(evl->evl_shost, ar_tha(arp), ETHER_ADDR_LEN);

	/*
	 * Set sender mac address to the one set via setenaddr.
	 * Source mac will be set by ng_ether(4) due to setautosrc flag.
	 */
	bcopy(priv->mac, ar_sha(arp), ETHER_ADDR_LEN);

	/* Swap source and target IP addresses. */
	bcopy(ar_tpa(arp), ar_spa(arp), sizeof(struct in_addr));
	bcopy(&arp_entry->ip, ar_tpa(arp), sizeof(struct in_addr));

	return (m);
}

/*
 * Allocate the private data structure. The generic node has already
 * been created. Link them together. We arrive with a reference to the node
 * i.e. the reference count is incremented for us already.
 *
 * If this were a device node than this work would be done in the attach()
 * routine and the constructor would return EINVAL as you should not be able
 * to creatednodes that depend on hardware (unless you can add the hardware :)
 */
static int
ng_qwe_constructor(node_p node)
{
	private_p priv;

	/* Initialize private descriptor */
	priv = malloc(sizeof(*priv), M_NETGRAPH, M_WAITOK | M_ZERO);

	LIST_INIT(&priv->filters);

	/* Link together node and private info */
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	return (0);
}

static int
ng_qwe_newhook(node_p node, hook_p hook, const char *name)
{
	private_p	priv = NG_NODE_PRIVATE(node);
	struct filter	*f = NULL;

	NG_HOOK_SET_PRIVATE(hook, NULL);

	if (strcmp(name, NG_QWE_HOOK_NOMATCH) == 0)
		priv->nomatch = hook;
	else if (strcmp(name, NG_QWE_HOOK_DOWNSTREAM) == 0)
		priv->downstream = hook;
	else if (strcmp(name, NG_QWE_HOOK_SERVICE) == 0)
		priv->service = hook;
	else {
		/*
		 * Any other hook name is valid and can
		 * later be associated with a vlan tag pair.
		 */
		f = malloc(sizeof(*f), M_NETGRAPH, M_NOWAIT | M_ZERO);

		if (f == NULL)
			return (ENOMEM);

		/* Initialize arp table for this vlan. */
		LIST_INIT(&f->arp_table);

		/* Link filter and hook together. */
		f->hook = hook;
		NG_HOOK_SET_PRIVATE(hook, f);
	}

	return (0);
}

static int
ng_qwe_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const private_p priv = NG_NODE_PRIVATE(node);
	int error = 0;
	struct ng_mesg		*msg, *resp = NULL;
	struct ng_qwe_filter	*vf = NULL;
	struct ng_qwe_arp	*varp = NULL;
	hook_p hook = NULL;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command. */
	switch (msg->header.typecookie) {
	case NGM_QWE_COOKIE:
		switch (msg->header.cmd) {
		case NGM_QWE_ADD_FILTER:
			/* Check that message is long enough. */
			if (msg->header.arglen != sizeof(*vf)) {
				error = EINVAL;
				break;
			}
			vf = (struct ng_qwe_filter *)msg->data;
			/* Sanity check the VLAN ID values. */
			if (IS_INVALID_VLAN(vf->outer_vlan) ||
			    IS_INVALID_VLAN(vf->inner_vlan)) {
				error = EINVAL;
				break;
			}
			/* Check that a referenced hook exists. */
			hook = ng_findhook(node, vf->hook);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}
			/* And is not one of the special hooks. */
			if (hook == priv->downstream ||
			    hook == priv->service ||
			    hook == priv->nomatch) {
				error = EINVAL;
				break;
			}
			/* And is not already in service. */
			if (IS_HOOK_IN_SERVICE(hook)) {
				error = EEXIST;
				break;
			}
			/* Check we don't already trap these VLANs. */
			if (ng_qwe_find_entry(priv, vf->outer_vlan,
			    vf->inner_vlan)) {
				error = EEXIST;
				break;
			}
			/* Register filter. */
			ng_qwe_add_filter(hook,
			    vf->outer_vlan, vf->inner_vlan);
			break;
		case NGM_QWE_DEL_FILTER:
			/* Check that message is long enough. */
			if (msg->header.arglen != NG_HOOKSIZ) {
				error = EINVAL;
				break;
			}
			/* Check that hook exists and is active. */
			hook = ng_findhook(node, (char *)msg->data);
			if (hook == NULL || !IS_HOOK_IN_SERVICE(hook)) {
				error = ENOENT;
				break;
			}
			/* Unregister filter. */
			ng_qwe_del_filter(hook);
			break;
		case NGM_QWE_ADD_ARP:
			/* Check that message is long enough. */
			if (msg->header.arglen != sizeof(*varp)) {
				error = EINVAL;
				break;
			}
			varp = (struct ng_qwe_arp *)msg->data;
			/* Check that a referenced hook exists. */
			hook = ng_findhook(node, varp->hook);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}
			/* And is not one of the special hooks. */
			if (hook == priv->downstream ||
			    hook == priv->service ||
			    hook == priv->nomatch) {
				error = EINVAL;
				break;
			}

			/* Validate IP and MAC. */
			if (!ng_qwe_is_valid_arp(&varp->ip, varp->mac)) {
				error = EINVAL;
				break;
			}

			error = ng_qwe_add_arp(hook, &varp->ip, varp->mac);
			break;
		case NGM_QWE_DEL_ARP:
			/* Check that message is long enough. */
			if (msg->header.arglen != sizeof(*varp)) {
				error = EINVAL;
				break;
			}
			varp = (struct ng_qwe_arp *)msg->data;
			/* Check that a referenced hook exists. */
			hook = ng_findhook(node, varp->hook);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}
			/* And is not one of the special hooks. */
			if (hook == priv->downstream ||
			    hook == priv->service ||
			    hook == priv->nomatch) {
				error = EINVAL;
				break;
			}

			error = ng_qwe_del_arp(hook, &varp->ip, varp->mac);
			break;
		case NGM_QWE_GET_ENADDR:
			NG_MKRESPONSE(resp, msg, ETHER_ADDR_LEN, M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			bcopy(priv->mac, resp->data, ETHER_ADDR_LEN);
			break;
		case NGM_QWE_SET_ENADDR:
			/* Check that message is long enough. */
			if (msg->header.arglen != ETHER_ADDR_LEN) {
				error = EINVAL;
				break;
			}
			bcopy(msg->data, priv->mac, ETHER_ADDR_LEN);
			break;
		case NGM_QWE_GET_CONFIG:
		    {
			struct filter		*filter = NULL;
			struct ng_qwe_config	*config = NULL;
			struct arp_entry	*src_arp;
			struct ng_qwe_arp_entry	*dst_arp;

			/* Check that message is long enough. */
			if (msg->header.arglen != NG_HOOKSIZ) {
				error = EINVAL;
				break;
			}
			/* Check that hook exists. */
			hook = ng_findhook(node, (char *)msg->data);
			if (hook == NULL) {
				error = ENOENT;
				break;
			}
			/* And is not one of the special hooks. */
			if (hook == priv->downstream ||
			    hook == priv->service ||
			    hook == priv->nomatch) {
				error = EINVAL;
				break;
			}
			filter = NG_HOOK_PRIVATE(hook);
			NG_MKRESPONSE(resp, msg, sizeof(*config) +
			    filter->arp_len * sizeof(*config->arp), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			config = (struct ng_qwe_config *)resp->data;
			config->outer_vlan = filter->outer_vlan;
			config->inner_vlan = filter->inner_vlan;
			config->arp_len = filter->arp_len;
			dst_arp = config->arp;
			LIST_FOREACH(src_arp, &filter->arp_table, next) {
				bcopy(&src_arp->ip, &dst_arp->ip,
				    sizeof(dst_arp->ip));
				bcopy(src_arp->mac, dst_arp->mac,
				    ETHER_ADDR_LEN);
				++dst_arp;
			}
			break;
		    }
		default:		/* Unknown command. */
			error = EINVAL;
			break;
		}
		break;
#if 0
	case NGM_FLOW_COOKIE:
	    {
		struct ng_mesg *copy;
		struct filterhead *chain;
		struct filter *f;

		/*
		 * Flow control messages should come only
		 * from downstream.
		 */

		if (lasthook == NULL)
			break;
		if (lasthook != priv->downstream_hook)
			break;

		/* Broadcast the event to all uplinks. */
		for (i = 0, chain = priv->hashtable; i < HASHSIZE;
		    i++, chain++)
		LIST_FOREACH(f, chain, next) {
			NG_COPYMESSAGE(copy, msg, M_NOWAIT);
			if (copy == NULL)
				continue;
			NG_SEND_MSG_HOOK(error, node, copy, f->hook, 0);
		}

		break;
	    }
#endif
	default:			/* Unknown type cookie. */
		error = EINVAL;
		break;
	}
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	return (error);
}

static int
ng_qwe_rcvdata(hook_p hook, item_p item)
{
	const private_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	int		error = 0;
	struct mbuf	*m = NULL;
	struct ether_vlan_header *evl = NULL;
	struct ip	*ip = NULL;
	struct udphdr	*udp = NULL;
	struct filter	*target_filter = NULL;
	struct arp_entry	*arp = NULL;

#define FORWARD_AND_RETURN(hook) \
	do { \
		NG_FWD_NEW_DATA(error, item, (hook), m); \
		return (error); \
	} while (0)

	if (priv->downstream == NULL) {
		/* There's nothing to do actually. */
		NG_FREE_ITEM(item);
		return (0);
	}

	NGI_GET_M(item, m);
	if (hook == priv->nomatch) {
		/* Forward from nomatch to downstream as is. */
		FORWARD_AND_RETURN(priv->downstream);
	}
	if (hook == priv->downstream) {
		/*
		 * Decide where to deliver the packet to.
		 * We aren't sure that the packet is a QinQ one.
		 */
		if (((m->m_flags & M_VLANTAG) == 0)
		    || (m->m_pkthdr.len < sizeof(*evl))) {
			/* No outer tag. */
			FORWARD_AND_RETURN(priv->nomatch);
		}

		if (m->m_len < sizeof(*evl) &&
		    (m = m_pullup(m, sizeof(*evl))) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		evl = mtod(m, struct ether_vlan_header *);

		if (evl->evl_encap_proto != htons(ETHERTYPE_VLAN)) 
			/* No inner tag. */
			FORWARD_AND_RETURN(priv->nomatch);

		if (evl->evl_proto == htons(ETHERTYPE_ARP)) {
			/*
			 * We serve as a simplistic ARP proxy.
			 * So try to process QinQ ARP packet right here.
			 */

			m = ng_qwe_process_arp(m, priv);
			if (m == NULL) {
				NG_FREE_ITEM(item);
				return (0);
			}
			/*
			 * If we got an ARP reply packet send it
			 * back to the wire.
			 */
			FORWARD_AND_RETURN(priv->downstream);
		}

		if (evl->evl_proto != htons(ETHERTYPE_IP))
			FORWARD_AND_RETURN(priv->nomatch);

		/* Dig into IPv4 and UDP to check for DHCP. */
		if (m->m_len < sizeof(*evl) + sizeof(*ip) &&
		    (m = m_pullup(m, sizeof(*evl) + sizeof(*ip))) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		ip = (struct ip *)(mtod(m, char *) + sizeof(*evl));

		if ((ip->ip_v != IPVERSION) || (ip->ip_hl < 5))
			/* Forward a non-IP packet to nomatch as well. */
			FORWARD_AND_RETURN(priv->nomatch);

		/*
		 * Hereinafter we got QinQ IP packet.
		 * Though it still might be a service one (in case
		 * it turns out to be DHCP) it is now a candidate
		 * for vlan hook delivery.
		 */
		if (ip->ip_p == IPPROTO_UDP) {
			if (m->m_len < sizeof(*evl) + sizeof(*ip) +
			    sizeof(*udp) &&
			    (m = m_pullup(m, sizeof(*evl) + sizeof(*ip) +
			    sizeof(*udp))) == NULL) {
				NG_FREE_ITEM(item);
				return (EINVAL);
			}

			udp = (struct udphdr *)((char *)ip + (ip->ip_hl << 2));
			if (IS_DHCP(udp)) {
				/*
				 * QinQ DHCP traffic is a service one.
				 * Extract vlan tag from mbuf packet header
				 * and place it into the body itself before
				 * delivery.
				 */

				m = ether_vlanencap(m, m->m_pkthdr.ether_vtag);
				if (m == NULL) {
					NG_FREE_ITEM(item);
					return (ENOMEM);
				}
				FORWARD_AND_RETURN(priv->service);
			}
		}

		/*
		 * Now we are sure that we got a QinQ IP packet
		 * that is not a service packet.
		 *
		 * Try to find a vlan hook for it otherwise deliver to nomatch.
		 */
		target_filter = ng_qwe_find_entry(priv,
		    EVL_VLANOFTAG(m->m_pkthdr.ether_vtag),
		    EVL_VLANOFTAG(ntohs(evl->evl_tag)));

		if (target_filter != NULL) {
			/*
			 * Target hook found.
			 * Check against ARP table.
			 */

			if (ng_qwe_find_arp(target_filter->hook, &ip->ip_src,
			    evl->evl_shost) == NULL) {
				/*
				 * No entry in ARP found.
				 * Drop the packet.
				 */
				NG_FREE_M(m);
				NG_FREE_ITEM(item);

				/* XXX: Increment error counter. */
				return (0);
			}

			/*
			 * Since we are doing IP over Ethernet 
			 * the target node expects no Ethernet header 
			 * so strip it.
			 */
			m->m_flags &= ~M_VLANTAG;
			m->m_pkthdr.ether_vtag = 0;
			m_adj(m, sizeof(*evl));

			FORWARD_AND_RETURN(target_filter->hook);
		}
		/*
		 * Target hook not found.
		 * Deliver to nomatch as is.
		 */
		FORWARD_AND_RETURN(priv->nomatch);
	} else if (hook == priv->service) {
		/*
		 * We care only about QinQ traffic with both tags
		 * stored inbound.
		 */
		if (m->m_flags & M_VLANTAG) {
			NG_FREE_M(m);
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		if (m->m_len < sizeof(*evl) + ETHER_VLAN_ENCAP_LEN &&
		    (m = m_pullup(m, sizeof(*evl) +
		    ETHER_VLAN_ENCAP_LEN)) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		/* Make sure we really got a QinQ packet. */
		evl = mtod(m, struct ether_vlan_header *);
		if ((evl->evl_encap_proto != htons(ETHERTYPE_VLAN)) ||
		    (evl->evl_proto != htons(ETHERTYPE_VLAN))) {
		       NG_FREE_M(m);
		       NG_FREE_ITEM(item);
		       return (EINVAL);
		}

		/*
		 * Move the outter tag from Ethernet header
		 * to mbuf header.
		 */
		m->m_pkthdr.ether_vtag = evl->evl_encap_proto;
		m->m_flags |= M_VLANTAG;

		bcopy(mtod(m, char *),
		    mtod(m, char *) + ETHER_VLAN_ENCAP_LEN,
		    ETHER_HDR_LEN - ETHER_TYPE_LEN);

		m_adj(m, ETHER_VLAN_ENCAP_LEN);

		FORWARD_AND_RETURN(priv->downstream);
	} else {
		/* Packet is coming from one of vlan hooks. */
		target_filter = NG_HOOK_PRIVATE(hook);
		if (target_filter == NULL ||
		    !IS_FILTER_IN_SERVICE(target_filter)) {
			/*
			 * Discard packet if no filter added to this vlan hook.
			 */

			NG_FREE_M(m);
			NG_FREE_ITEM(item);
			return (0);
		}

		/* Dig into IP to find out dst IP. */
		if (m->m_len < sizeof(*ip) &&
		    (m = m_pullup(m, sizeof(*ip))) == NULL) {
			NG_FREE_M(m);
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		ip = mtod(m, struct ip *);
		arp = ng_qwe_find_arp(hook, &ip->ip_dst, NULL);
		if (arp == NULL) {
			/*
			 * Discard packet as there's no ARP entry for it.
			 */

			NG_FREE_M(m);
			NG_FREE_ITEM(item);
			return (0);
		}

		/* Prepend a Ethernet header with 802.1q encapsulation. */
		M_PREPEND(m, sizeof(*evl), M_DONTWAIT);
		if (m == NULL) {
			NG_FREE_ITEM(item);
			return (ENOMEM);
		}

		evl = mtod(m, struct ether_vlan_header *);

		/*
		 * Copy destination MAC address from ARP entry.
		 * Source MAC address will be set by ng_ether upon delivery.
		 */
		bcopy(arp->mac, evl->evl_dhost, ETHER_ADDR_LEN);

		/* Inject outer vlan tag. */
		m->m_pkthdr.ether_vtag = target_filter->outer_vlan;
		m->m_flags |= M_VLANTAG;

		/* Inject inner vlan tag. */
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = htons(target_filter->inner_vlan);

		/* Make it an IP packet. */
		evl->evl_proto = htons(ETHERTYPE_IP);

		FORWARD_AND_RETURN(priv->downstream);
	}

#undef FORWARD_AND_RETURN
}

/*
 * Do local shutdown processing.
 */
static int
ng_qwe_shutdown(node_p node)
{
	const private_p	priv = NG_NODE_PRIVATE(node);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	free(priv, M_NETGRAPH);

	return (0);
}


/*
 * Hook disconnection
 *
 * For this type, removal of the last link destroys the node
 */
static int
ng_qwe_disconnect(hook_p hook)
{
	const private_p priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct filter *filter = NG_HOOK_PRIVATE(hook);
	struct arp_entry *arp1, *arp2;
	
	if (hook == priv->nomatch)
		priv->nomatch = NULL;
	else if (hook == priv->downstream)
		priv->downstream = NULL;
	else if (hook == priv->service)
		priv->service = NULL;
	else {
		KASSERT(filter != NULL,
		    ("disconnecting vlan hook without a filter attached"));
		/* Free tags structure cleaning arp table first. */
		arp1 = LIST_FIRST(&filter->arp_table);
		while (arp1 != NULL) {
		     arp2 = LIST_NEXT(arp1, next);
		     free(arp1, M_NETGRAPH);
		     arp1 = arp2;
		}
		/*
		 * No need to init the arp table list head
		 * since we are deleting the filter anyway.
		 */
		free(filter, M_NETGRAPH);
	}
	NG_HOOK_SET_PRIVATE(hook, NULL);

	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	    && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {
		ng_rmnode_self(NG_HOOK_NODE(hook));
	}

	return (0);
}

