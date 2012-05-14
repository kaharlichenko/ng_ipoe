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
#include <netgraph/netgraph.h>

#include "ng_qwe.h"

#define IS_DHCP(udp) \
( \
(((udp)->uh_sport == htons(67)) && ((udp)->uh_dport == htons(68))) || \
(((udp)->uh_sport == htons(68)) && ((udp)->uh_dport == htons(67))) \
)

/*
 * This section contains the netgraph method declarations for the
 * qwe node. These methods define the netgraph 'type'.
 */

static ng_constructor_t	ng_qwe_constructor;
static ng_shutdown_t	ng_qwe_shutdown;
static ng_newhook_t	ng_qwe_newhook;
static ng_rcvdata_t	ng_qwe_rcvdata;
static ng_disconnect_t	ng_qwe_disconnect;


/* Netgraph node type descriptor */
static struct ng_type typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_QWE_NODE_TYPE,
	.constructor =	ng_qwe_constructor,
	.shutdown =	ng_qwe_shutdown,
	.newhook =	ng_qwe_newhook,
	.rcvdata =	ng_qwe_rcvdata,
	.disconnect =	ng_qwe_disconnect,
};
NETGRAPH_INIT(qwe, &typestruct);


/* Information we store for each node */
struct ng_qwe_private {
	hook_p  	nomatch;
	hook_p  	downstream;
	hook_p  	service;
	node_p		node;		/* back pointer to node */
};
typedef struct ng_qwe_private *private_p;

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

	/* Link together node and private info */
	NG_NODE_SET_PRIVATE(node, priv);
	priv->node = node;

	return (0);
}

/*
 * Give our ok for a hook to be added...
 */
static int
ng_qwe_newhook(node_p node, hook_p hook, const char *name)
{
	private_p	priv = NG_NODE_PRIVATE(node);
	hook_p		*localhook;

	if (strcmp(name, NG_QWE_HOOK_NOMATCH) == 0) {
		localhook = &priv->nomatch;
	} else if (strcmp(name, NG_QWE_HOOK_DOWNSTREAM) == 0) {
		localhook = &priv->downstream;
	} else if (strcmp(name, NG_QWE_HOOK_SERVICE) == 0) {
		localhook = &priv->service;
	} else
		return (EINVAL);

	if (*localhook != NULL)
		return (EISCONN);

	*localhook = hook;
	NG_HOOK_SET_PRIVATE(hook, localhook);

	return(0);
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
	hook_p		target = priv->nomatch;
	int		error = 0;
	struct mbuf	*m = NULL;
	struct ether_vlan_header *evl = NULL;
	struct ip	*ip = NULL;
	struct udphdr	*udp = NULL;

	NGI_GET_M(item, m);
	if (hook == priv->nomatch) {
		/* Forward from nomatch to downstream as is. */
		target = priv->downstream;
		goto deliver;
	} else if (hook == priv->downstream) {
		/* TODO: Factor out into ng_qwe_is_service() */
		if (((m->m_flags & M_VLANTAG) == 0)
		    || (m->m_pkthdr.len < sizeof(*evl))) {
			/*
			 * We care only about QinQ traffic.
			 * Deliver to nomatch.
			 */
			goto deliver;
		}

		if (m->m_len < sizeof(*evl) &&
		    (m = m_pullup(m, sizeof(*evl))) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		evl = mtod(m, struct ether_vlan_header *);

		/* Inner tag must also be present. */
		if (evl->evl_encap_proto != htons(ETHERTYPE_VLAN)) 
			/*
			 * We care only about QinQ traffic.
			 * Deliver to nomatch.
			 */
			goto deliver;

		if (evl->evl_proto == htons(ETHERTYPE_ARP)) {
			target = priv->service;
			goto inject_tag;
		}

		if (evl->evl_proto != htons(ETHERTYPE_IP))
			goto deliver;
	
		/* Dig into IPv4 and UDP to check for DHCP */
		if (m->m_len < sizeof(*evl) + sizeof(*ip) &&
		    (m = m_pullup(m, sizeof(*evl) + sizeof(*ip))) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		ip = (struct ip *)(mtod(m, char *) + sizeof(*evl));

		if ((ip->ip_v != IPVERSION) || (ip->ip_hl < 5) ||
		    (ip->ip_p != IPPROTO_UDP)) {
			goto deliver;
		}

		if (m->m_len < sizeof(*evl) + sizeof(*ip) + sizeof(*udp) &&
		    (m = m_pullup(m, sizeof(*evl) + sizeof(*ip) +
		    sizeof(*udp))) == NULL) {
			NG_FREE_ITEM(item);
			return (EINVAL);
		}

		udp = (struct udphdr *)((char *)ip + (ip->ip_hl << 2));
		if (!IS_DHCP(udp))
			goto deliver;

		target = priv->service;
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

		target = priv->downstream;
		goto deliver;
	} else {
		/* TODO: Handle vlan hooks */; 
		target = NULL;
		goto deliver;
	}

inject_tag:
	/*
	 * Packet is heading towards service hook.
	 * Extract vlan tag from mbuf packet header and place it
	 * into the body itself before delivery.
	 */

	m = ether_vlanencap(m, m->m_pkthdr.ether_vtag);
	if (m == NULL) {
		NG_FREE_ITEM(item);
		return (ENOMEM);
	}

deliver:
	if (target != NULL)
		NG_FWD_NEW_DATA(error, item, target, m);

	if (item) {
		NG_FREE_M(m);
		NG_FREE_ITEM(item);
	}

	return (error);
}

/*
 * Do local shutdown processing..
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
	hook_p *localhook = NG_HOOK_PRIVATE(hook);
	
	KASSERT(localhook != NULL, ("%s: null info", __func__));
	*localhook = NULL;
	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	    && (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {
		ng_rmnode_self(NG_HOOK_NODE(hook));
	}

	return (0);
}

