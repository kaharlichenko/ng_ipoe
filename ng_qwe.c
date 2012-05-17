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

static const struct ng_cmdlist ng_qwe_cmdlist[] = {
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_ADD_FILTER,
	  "addfilter",
	  &ng_qwe_filter_type,
	  NULL
	},
#if 0
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_DEL_FILTER,
	  "delfilter",
	  &ng_parse_hookbuf_type,
	  NULL
	},
	{
	  NGM_QWE_COOKIE,
	  NGM_QWE_GET_TABLE,
	  "gettable",
	  NULL,
	  &ng_qwe_table_type
	},
#endif
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
struct filter {
	LIST_ENTRY(filter) next;
	u_int16_t	outer_vlan;
	u_int16_t	inner_vlan;
	hook_p		hook;
};

LIST_HEAD(filterhead, filter);

struct ng_qwe_private {
	hook_p  	nomatch;
	hook_p  	downstream;
	hook_p  	service;
	struct filterhead filters;
	node_p		node;		/* back pointer to node */
};
typedef struct ng_qwe_private *private_p;

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

static int
ng_qwe_create_entry(hook_p hook, 
    u_int16_t outer_vlan, u_int16_t inner_vlan)
{
	private_p node_priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	struct filter *f = malloc(sizeof(*f), M_NETGRAPH, M_NOWAIT | M_ZERO);

	if (f == NULL)
		return (0);

	/* Link filter and hook together. */
	f->hook = hook;
	f->outer_vlan = outer_vlan;
	f->inner_vlan = inner_vlan;
	NG_HOOK_SET_PRIVATE(hook, f);

	/* Register filter in a filter list. */
	LIST_INSERT_HEAD(&node_priv->filters, f, next);
	/* priv->nent++;*/

	return (1);
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

	if (strcmp(name, NG_QWE_HOOK_NOMATCH) == 0)
		priv->nomatch = hook;
	else if (strcmp(name, NG_QWE_HOOK_DOWNSTREAM) == 0)
	      priv->downstream = hook;
	else if (strcmp(name, NG_QWE_HOOK_SERVICE) == 0)
	      priv->service = hook;
	else {
		/* TODO: Allocate vlan hook structure on creation. */
		/*
		 * Any other hook name is valid and can
		 * later be associated with vlan tag pair.
		 */
	}

	NG_HOOK_SET_PRIVATE(hook, NULL);

	return (0);
}

static int
ng_qwe_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const private_p priv = NG_NODE_PRIVATE(node);
	int error = 0;
	struct ng_mesg *msg, *resp = NULL;
	struct ng_qwe_filter *vf;
	hook_p hook;

	/* TODO: Implement setaddr message. */

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
			if (NG_HOOK_PRIVATE(hook) != NULL) {
				error = EEXIST;
				break;
			}
			/* Check we don't already trap these VLANs. */
			if (ng_qwe_find_entry(priv, vf->outer_vlan,
			    vf->inner_vlan)) {
				error = EEXIST;
				break;
			}
			/* Create filter. */
			if (!ng_qwe_create_entry(hook,
			    vf->outer_vlan, vf->inner_vlan)) {
				error = ENOMEM;
				break;
			}
			break;
#if 0
		case NGM_QWE_DEL_FILTER:
			/* Check that message is long enough. */
			if (msg->header.arglen != NG_HOOKSIZ) {
				error = EINVAL;
				break;
			}
			/* Check that hook exists and is active. */
			hook = ng_findhook(node, (char *)msg->data);
			if (hook == NULL ||
			    (f = NG_HOOK_PRIVATE(hook)) == NULL) {
				error = ENOENT;
				break;
			}
			/* Purge a rule that refers to this hook. */
			NG_HOOK_SET_PRIVATE(hook, NULL);
			LIST_REMOVE(f, next);
			priv->nent--;
			free(f, M_NETGRAPH);
			break;
		case NGM_QWE_GET_TABLE:
			NG_MKRESPONSE(resp, msg, sizeof(*t) +
			    priv->nent * sizeof(*t->filter), M_NOWAIT);
			if (resp == NULL) {
				error = ENOMEM;
				break;
			}
			t = (struct ng_vlan_table *)resp->data;
			t->n = priv->nent;
			vf = &t->filter[0];
			for (i = 0; i < HASHSIZE; i++) {
				LIST_FOREACH(f, &priv->hashtable[i], next) {
					vf->vlan = f->vlan;
					strncpy(vf->hook, NG_HOOK_NAME(f->hook),
					    NG_HOOKSIZ);
					vf++;
				}
			}
			break;
#endif
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

/*
 * Receive data, and do something with it.
 * Actually we receive a queue item which holds the data.
 * If we free the item it will also free the data unless we have
 * previously disassociated it using the NGI_GET_M() macro.
 * Possibly send it out on another link after processing.
 * Possibly do something different if it comes from different
 * hooks. The caller will never free m, so if we use up this data or
 * abort we must free it.
 *
 * If we want, we may decide to force this data to be queued and reprocessed
 * at the netgraph NETISR time.
 * We would do that by setting the HK_QUEUE flag on our hook. We would do that
 * in the connect() method.
 */
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
			 * QinQ ARP traffic is a service one.
			 * Extract vlan tag from mbuf packet header
			 * and place it into the body itself before delivery.
			 */

			m = ether_vlanencap(m, m->m_pkthdr.ether_vtag);
			if (m == NULL) {
				NG_FREE_ITEM(item);
				return (ENOMEM);
			}
			FORWARD_AND_RETURN(priv->service);
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
			 * Since we are doing IP over Ethernet 
			 * the target node expects no Ethernet header 
			 * so strip it.
			 */
			m->m_flags &= ~M_VLANTAG;
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
		/* TODO: Handle packets coming from vlan hooks. */
		NG_FREE_M(m);
		NG_FREE_ITEM(item);
		return (0);
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
	
	if (hook == priv->nomatch)
		priv->nomatch = NULL;
	else if (hook == priv->downstream)
		priv->downstream = NULL;
	else if (hook == priv->service)
		priv->service = NULL;
	else {
		/* TODO: Free tags structure. */
	}
	NG_HOOK_SET_PRIVATE(hook, NULL);

	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	    && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {
		ng_rmnode_self(NG_HOOK_NODE(hook));
	}

	return (0);
}

