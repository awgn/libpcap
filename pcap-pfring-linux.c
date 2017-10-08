/*
 *  pcap-linux.c: Packet capture interface to the Linux kernel
 *
 *  Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *  		       Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 *
 *  License: BSD
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  Modifications:     Added PACKET_MMAP support
 *                     Paolo Abeni <paolo.abeni@email.it>
 *                     Added TPACKET_V3 support
 *                     Gabor Tatarka <gabor.tatarka@ericsson.com>
 *
 *                     based on previous works of:
 *                     Simon Patarin <patarin@cs.unibo.it>
 *                     Phil Wood <cpw@lanl.gov>
 *
 * Monitor-mode support for mac80211 includes code taken from the iw
 * command; the copyright notice for that code is
 *
 * Copyright (c) 2007, 2008	Johannes Berg
 * Copyright (c) 2007		Andy Lutomirski
 * Copyright (c) 2007		Mike Kershaw
 * Copyright (c) 2008		Gábor Stefanik
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Known problems with 2.0[.x] kernels:
 *
 *   - The loopback device gives every packet twice; on 2.2[.x] kernels,
 *     if we use PF_PACKET, we can filter out the transmitted version
 *     of the packet by using data in the "sockaddr_ll" returned by
 *     "recvfrom()", but, on 2.0[.x] kernels, we have to use
 *     PF_INET/SOCK_PACKET, which means "recvfrom()" supplies a
 *     "sockaddr_pkt" which doesn't give us enough information to let
 *     us do that.
 *
 *   - We have to set the interface's IFF_PROMISC flag ourselves, if
 *     we're to run in promiscuous mode, which means we have to turn
 *     it off ourselves when we're done; the kernel doesn't keep track
 *     of how many sockets are listening promiscuously, which means
 *     it won't get turned off automatically when no sockets are
 *     listening promiscuously.  We catch "pcap_close()" and, for
 *     interfaces we put into promiscuous mode, take them out of
 *     promiscuous mode - which isn't necessarily the right thing to
 *     do, if another socket also requested promiscuous mode between
 *     the time when we opened the socket and the time when we close
 *     the socket.
 *
 *   - MSG_TRUNC isn't supported, so you can't specify that "recvfrom()"
 *     return the amount of data that you could have read, rather than
 *     the amount that was returned, so we can't just allocate a buffer
 *     whose size is the snapshot length and pass the snapshot length
 *     as the byte count, and also pass MSG_TRUNC, so that the return
 *     value tells us how long the packet was on the wire.
 *
 *     This means that, if we want to get the actual size of the packet,
 *     so we can return it in the "len" field of the packet header,
 *     we have to read the entire packet, not just the part that fits
 *     within the snapshot length, and thus waste CPU time copying data
 *     from the kernel that our caller won't see.
 *
 *     We have to get the actual size, and supply it in "len", because
 *     otherwise, the IP dissector in tcpdump, for example, will complain
 *     about "truncated-ip", as the packet will appear to have been
 *     shorter, on the wire, than the IP header said it should have been.
 */


#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <poll.h>
#include <dirent.h>

#include "pcap-int.h"
#include "pcap/sll.h"
#include "pcap/vlan.h"

#include "pcap-pfring-linux.h"

#ifdef SO_ATTACH_FILTER
#include <linux/types.h>
#include <linux/filter.h>
#endif

#ifdef HAVE_LINUX_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_LINUX_IF_BONDING_H
#include <linux/if_bonding.h>
#endif

/*
 * Got Wireless Extensions?
 */
#ifdef HAVE_LINUX_WIRELESS_H
#include <linux/wireless.h>
#endif /* HAVE_LINUX_WIRELESS_H */

/*
 * Got libnl?
 */

/*
 * Got ethtool support?
 */
#ifdef HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h>
#endif

#ifndef HAVE_SOCKLEN_T
typedef int		socklen_t;
#endif

#ifndef MSG_TRUNC
/*
 * This is being compiled on a system that lacks MSG_TRUNC; define it
 * with the value it has in the 2.2 and later kernels, so that, on
 * those kernels, when we pass it in the flags argument to "recvfrom()"
 * we're passing the right value and thus get the MSG_TRUNC behavior
 * we want.  (We don't get that behavior on 2.0[.x] kernels, because
 * they didn't support MSG_TRUNC.)
 */
#define MSG_TRUNC	0x20
#endif

#ifndef SOL_PACKET
/*
 * This is being compiled on a system that lacks SOL_PACKET; define it
 * with the value it has in the 2.2 and later kernels, so that we can
 * set promiscuous mode in the good modern way rather than the old
 * 2.0-kernel crappy way.
 */
#define SOL_PACKET	263
#endif

#define MAX_LINKHEADER_SIZE	256

/*
 * When capturing on all interfaces we use this as the buffer size.
 * Should be bigger then all MTUs that occur in real life.
 * 64kB should be enough for now.
 */
#define BIGGER_THAN_ALL_MTUS	(64*1024)

/*
 * Private data for capturing on Linux SOCK_PACKET or PF_PACKET sockets.
 */
struct pcap_linux {
	u_int	packets_read;	/* count of packets read with recvfrom() */
	long	proc_dropped;	/* packets reported dropped by /proc/net/dev */
	struct pcap_stat stat;

	char	*device;	/* device name */
	int	filter_in_userland; /* must filter in userland */
	int	blocks_to_filter_in_userland;
	int	must_do_on_close; /* stuff we must do when we close */
	int	timeout;	/* timeout for buffering */
	int	sock_packet;	/* using Linux 2.0 compatible interface */
	int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
	int	ifindex;	/* interface index of device we're bound to */
	int	lo_ifindex;	/* interface index of the loopback device */
	bpf_u_int32 oldmode;	/* mode to restore when turning monitor mode off */
	char	*mondevice;	/* mac80211 monitor device we created */
	u_char	*mmapbuf;	/* memory-mapped region pointer */
	size_t	mmapbuflen;	/* size of region */
	int	vlan_offset;	/* offset at which to insert vlan tags; if -1, don't insert */
	u_int	tp_version;	/* version of tpacket_hdr for mmaped ring */
	u_int	tp_hdrlen;	/* hdrlen of tpacket_hdr for mmaped ring */
	u_char	*oneshot_buffer; /* buffer for copy of packet */
#ifdef HAVE_TPACKET3
	unsigned char *current_packet; /* Current packet within the TPACKET_V3 block. Move to next block if NULL. */
	int packets_left; /* Unhandled packets left within the block from previous call to pcap_read_linux_mmap_v3 in case of TPACKET_V3. */
#endif
};

/*
 * Stuff to do when we close.
 */
#define MUST_CLEAR_PROMISC	0x00000001	/* clear promiscuous mode */
#define MUST_CLEAR_RFMON	0x00000002	/* clear rfmon (monitor) mode */
#define MUST_DELETE_MONIF	0x00000004	/* delete monitor-mode interface */

/*
 * Prototypes for internal functions and methods.
 */

static int pfring_read_linux(pcap_t *, int, pcap_handler, u_char *);
static int pfring_read_packet(pcap_t *, pcap_handler, u_char *);
static int pfring_inject_linux(pcap_t *, const void *, size_t);
static int pfring_setfilter_linux(pcap_t *, struct bpf_program *);
static int pfring_setdirection_linux(pcap_t *, pcap_direction_t);
static int pfring_set_datalink_linux(pcap_t *, int);
static int pfring_stats_linux(pcap_t *handle, struct pcap_stat *stats);
static void pfring_cleanup_linux(pcap_t *);


static void pfring_cleanup_linux_mmap(pcap_t *);
static int pfring_setnonblock_mmap(pcap_t *p, int nonblock);
static int pfring_getnonblock_mmap(pcap_t *p);

#ifdef TP_STATUS_VLAN_TPID_VALID
# define VLAN_TPID(hdr, hv)	(((hv)->tp_vlan_tpid || ((hdr)->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? (hv)->tp_vlan_tpid : ETH_P_8021Q)
#else
# define VLAN_TPID(hdr, hv)	ETH_P_8021Q
#endif

/*
 * Wrap some ioctl calls
 */

#ifdef SO_ATTACH_FILTER
static int	fix_program(pcap_t *handle, struct sock_fprog *fcode,
    int is_mapped);
static int	fix_offset(struct bpf_insn *p);
static int	pfring_set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode);
static int	pfring_reset_kernel_filter(pcap_t *handle);

static struct sock_filter	total_insn
	= BPF_STMT(BPF_RET | BPF_K, 0);
static struct sock_fprog	total_fcode
	= { 1, &total_insn };
#endif /* SO_ATTACH_FILTER */

static u_int8_t pf_ring_active_poll = 0;



/*
 * Grabs the number of dropped packets by the interface from /proc/net/dev.
 *
 * XXX - what about /sys/class/net/{interface name}/rx_*?  There are
 * individual devices giving, in ASCII, various rx_ and tx_ statistics.
 *
 * Or can we get them in binary form from netlink?
 */
static long int
linux_if_drops(const char * if_name)
{
	char buffer[512];
	char * bufptr;
	FILE * file;
	int field_to_convert = 3, if_name_sz = strlen(if_name);
	long int dropped_pkts = 0;

	file = fopen("/proc/net/dev", "r");
	if (!file)
		return 0;

	while (!dropped_pkts && fgets( buffer, sizeof(buffer), file ))
	{
		/* 	search for 'bytes' -- if its in there, then
			that means we need to grab the fourth field. otherwise
			grab the third field. */
		if (field_to_convert != 4 && strstr(buffer, "bytes"))
		{
			field_to_convert = 4;
			continue;
		}

		/* find iface and make sure it actually matches -- space before the name and : after it */
		if ((bufptr = strstr(buffer, if_name)) &&
			(bufptr == buffer || *(bufptr-1) == ' ') &&
			*(bufptr + if_name_sz) == ':')
		{
			bufptr = bufptr + if_name_sz + 1;

			/* grab the nth field from it */
			while( --field_to_convert && *bufptr != '\0')
			{
				while (*bufptr != '\0' && *(bufptr++) == ' ');
				while (*bufptr != '\0' && *(bufptr++) != ' ');
			}

			/* get rid of any final spaces */
			while (*bufptr != '\0' && *bufptr == ' ') bufptr++;

			if (*bufptr != '\0')
				dropped_pkts = strtol(bufptr, NULL, 10);

			break;
		}
	}

	fclose(file);
	return dropped_pkts;
}


extern int pcap_update_config_from_env(pcap_t *handle, struct pcap_config *conf);

static int
pfring_update_config_from_env(pcap_t *handle, struct pcap_config *opt)
{
        /*
         * parse generic environment variables
         * */

        if (pcap_update_config_from_env(handle, opt) < 0)
                return -1;
        /*
         * parse specific PF_RING environment variables
         * */

	return 0;
}


/*
 * With older kernels promiscuous mode is kind of interesting because we
 * have to reset the interface before exiting. The problem can't really
 * be solved without some daemon taking care of managing usage counts.
 * If we put the interface into promiscuous mode, we set a flag indicating
 * that we must take it out of that mode when the interface is closed,
 * and, when closing the interface, if that flag is set we take it out
 * of promiscuous mode.
 *
 * Even with newer kernels, we have the same issue with rfmon mode.
 */

static void  pfring_cleanup_linux( pcap_t *handle )
{
	struct pcap_pfring_linux *handlep = handle->priv;
	struct ifreq	ifr;

	if (handlep->timeline != NULL) { free(handlep->timeline); handlep->timeline = NULL; }

	if (handlep->ring != NULL)
	{
		pfring_close(handlep->ring);
		handlep->ring = NULL;
	}

	if (handlep->mondevice != NULL) {
		free(handlep->mondevice);
		handlep->mondevice = NULL;
	}
	if (handlep->device != NULL) {
		free(handlep->device);
		handlep->device = NULL;
	}
}

static int pfring_is_dummy_interface(const char *device, char **path, char **interface)
{
	const char conf_root[] = "/var/tmp/pf_ring/dummy";
	const char type_token[]  = "type=";
	const char path_token[]  = "path=";
	const char interface_token[] = "interface=";
	char conf_path[256];
	char buffer[256];
	FILE *fd;

	*path = *interface = NULL;

	pcap_snprintf(conf_path, sizeof(conf_path), "%s/%s", conf_root, device);
	fd = fopen(conf_path, "r");
	if (fd == NULL) return 0; /* not a dummy interface */

	while (fgets(buffer, sizeof(buffer), fd)) {
		if (buffer[strlen(buffer) - 1] == '\n') buffer[strlen(buffer) - 1] = '\0';

		if (strncmp(buffer, type_token, sizeof(type_token) - 1) == 0) {
			// nothing to do
		} else if (strncmp(buffer, path_token, sizeof(path_token) - 1) == 0) {
			*path = strdup(&buffer[sizeof(path_token) - 1]);
		} else if (strncmp(buffer, interface_token, sizeof(interface_token) - 1) == 0) {
			*interface = strdup(&buffer[sizeof(interface_token) - 1]);
		}
	}

	fclose(fd);

	return 1;
}


static char *
pfring_get_devname(const char *fullname)
{
	char *dev;
	if (!fullname)
		return NULL;
	dev = strstr(fullname, "pfring");
	if (!dev)
		return strdup(fullname);
	if ((dev = strchr(dev, ':')))
		return strdup(dev+1);
	return NULL;
}


static
int pfring_fanout(pcap_t *handle, int group, const char *fanout)
{
	struct pcap_pfring_linux *handlep = handle->priv;
        unsigned int c;

        const char * algorithms[] = {
                  [cluster_per_flow                   ] = "flow"
        ,         [cluster_round_robin                ] = "round_robin"
        ,         [cluster_per_flow_2_tuple           ] = "flow_2_tuple"
        ,         [cluster_per_flow_4_tuple           ] = "flow_4_tuple"
        ,         [cluster_per_flow_5_tuple           ] = "flow_5_tuple"
        ,         [cluster_per_flow_tcp_5_tuple       ] = "flow_tcp_5_tuple"
        ,         [cluster_per_inner_flow             ] = "inner_flow"
        ,         [cluster_per_inner_flow_2_tuple     ] = "inner_flow_2_tuple"
        ,         [cluster_per_inner_flow_4_tuple     ] = "inner_flow_4_tuple"
        ,         [cluster_per_inner_flow_5_tuple     ] = "inner_flow_5_tuple"
        ,         [cluster_per_inner_flow_tcp_5_tuple ] = "inner_flow_tcp_5_tuple"
        };

        for(c = 0; c < sizeof(algorithms)/sizeof(algorithms[0]); c++)
        {
                if (strcmp(fanout, algorithms[c]) == 0) {
		        if (pfring_set_cluster(handlep->ring, group, c) < 0) {
                                pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "could not set fanout %s for group %d\n", fanout, group);
                                return PCAP_ERROR;
                        }
                        return 0;
                }
        }

        pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s: unsupported fanout algorithm", fanout);
        return PCAP_ERROR;
}


/*
 *  Get a handle for a live capture from the given device. You can
 *  pass NULL as device to get all packages (without link level
 *  information of course). If you pass 1 as promisc the interface
 *  will be set to promiscous mode (XXX: I think this usage should
 *  be deprecated and functions be added to select that later allow
 *  modification of that values -- Torsten).
 */
static int
pfring_activate_linux(pcap_t *handle)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	const char	*device;
	struct ifreq	ifr;
	int		status = 0;
	int		ret;

	device = pfring_get_devname(handle->opt.device);


	if (pfring_update_config_from_env(handle, &handle->opt.config) == -1) {
		return PCAP_ERROR;
	}

	handle->group = pcap_dev_map_get(&handle->opt.config.group_map, device);
	if (handle->group == -1)
		handle->group = handle->opt.config.group;


	/*
	 * Make sure the name we were handed will fit into the ioctls we
	 * might perform on the device; if not, return a "No such device"
	 * indication, as the Linux kernel shouldn't support creating
	 * a device whose name won't fit into those ioctls.
	 *
	 * "Will fit" means "will fit, complete with a null terminator",
	 * so if the length, which does *not* include the null terminator,
	 * is greater than *or equal to* the size of the field into which
	 * we'll be copying it, that won't fit.
	 */
	if (strlen(device) >= sizeof(ifr.ifr_name)) {
		status = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}

	handle->inject_op       = pfring_inject_linux;
	handle->setfilter_op    = pfring_setfilter_linux;
	handle->setdirection_op = pfring_setdirection_linux;
	handle->set_datalink_op = pfring_set_datalink_linux;
	handle->getnonblock_op  = pcap_getnonblock_fd;
	handle->setnonblock_op  = pcap_setnonblock_fd;
	handle->cleanup_op      = pfring_cleanup_linux;
	handle->read_op         = pfring_read_linux;
	handle->stats_op        = pfring_stats_linux;
	handle->fanout_op       = pfring_fanout;

	/*
	 * The "any" device is a special device which causes us not
	 * to bind to a particular device and thus to look at all
	 * devices.
	 */
	if (strcmp(device, "any") == 0) {
		if (handle->opt.promisc) {
			handle->opt.promisc = 0;
			/* Just a warning. */
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "Promiscuous mode not supported on the \"any\" device");
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

	handlep->device	= strdup(device);
	if (handlep->device == NULL) {
		pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "strdup: %s",
			 pcap_strerror(errno) );
		return PCAP_ERROR;
	}

	/* Code courtesy of Chris Wakelin <c.d.wakelin@reading.ac.uk> */
	char *clusterId;
	int flags = PF_RING_TIMESTAMP;
	char *appname, *active = getenv("PCAP_PF_RING_ACTIVE_POLL"), *rss_rehash;
	char timeline_device[256];
	char *real_device = NULL;

	if (handle->opt.promisc) flags |= PF_RING_PROMISC;
	if (getenv("PCAP_PF_RING_DNA_RSS" /* deprecated (backward compatibility) */ )) flags |= PF_RING_ZC_SYMMETRIC_RSS;
	if (getenv("PCAP_PF_RING_ZC_RSS"))  flags |= PF_RING_ZC_SYMMETRIC_RSS;
	if (getenv("PCAP_PF_RING_STRIP_HW_TIMESTAMP")) flags |= PF_RING_STRIP_HW_TIMESTAMP;
	if (getenv("PCAP_PF_RING_HW_TIMESTAMP") || handle->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO) flags |= PF_RING_HW_TIMESTAMP;

	if (active) pf_ring_active_poll = atoi(active);

	if (pfring_is_dummy_interface(device, &handlep->timeline, &real_device)) {
		if (real_device != NULL) {
			device = real_device;
		} else if (handlep->timeline) {
			pcap_snprintf(timeline_device, sizeof(timeline_device), "timeline:%s", handlep->timeline);
			device = timeline_device;
		}
	}

	handlep->ring = pfring_open((char *) device, handle->snapshot, flags);
	if (!handlep->ring) {
	        pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "Could not open pf_ring socket");
	        return PCAP_ERROR;
        }

	if (real_device != NULL) free(real_device);
	device = real_device = NULL;

	if (getenv("PCAP_PF_RING_RECV_ONLY")) pfring_set_socket_mode(handlep->ring, recv_only_mode);

        if (handle->group != -1)
        {
                char *fanout = handle->opt.config.fanout[handle->group];
                if (fanout) {
                        if (pfring_fanout(handle, handle->group, fanout) < 0) {
                                goto fail;
                        }
                }
        }

	if (clusterId = getenv("PCAP_PF_RING_CLUSTER_ID")) {
		if (atoi(clusterId) > 0 && atoi(clusterId) < 255) {
			if (getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW"))
				pfring_set_cluster(handlep->ring, atoi(clusterId), cluster_per_flow);
        		else if (getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_2_TUPLE"))
        			pfring_set_cluster(handlep->ring, atoi(clusterId), cluster_per_flow_2_tuple);
        		else if (getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE"))
        			pfring_set_cluster(handlep->ring, atoi(clusterId), cluster_per_flow_4_tuple);
        		else if (getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_TCP_5_TUPLE"))
        			pfring_set_cluster(handlep->ring, atoi(clusterId), cluster_per_flow_tcp_5_tuple);
        		else if (getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_5_TUPLE"))
        			pfring_set_cluster(handlep->ring, atoi(clusterId), cluster_per_flow_5_tuple);
			else
				pfring_set_cluster(handlep->ring, atoi(clusterId), cluster_round_robin);
        	}
	}

	if (appname = getenv("PCAP_PF_RING_APPNAME"))
	if (strlen(appname) > 0 && strlen(appname) <= 32)
		pfring_set_application_name(handlep->ring, appname);

	if (rss_rehash = getenv("PCAP_PF_RING_RSS_REHASH")) {
		if (atoi(rss_rehash))
			pfring_enable_rss_rehash(handlep->ring);
	}
	pfring_set_poll_watermark(handlep->ring, 1 /* watermark */);

	handle->fd = handlep->ring->fd;
	handle->bufsize = handle->snapshot;
	handle->linktype = DLT_EN10MB;
	handle->offset = 2;
	handle->setnonblock_op = pfring_setnonblock_mmap;
	handle->getnonblock_op = pfring_getnonblock_mmap;

	handlep->vlan_offset = -1; /* unknown */
	handlep->timeout = handle->opt.timeout; /* copy timeout value */

	/* Allocate the buffer */

	handle->buffer = malloc(handle->bufsize + handle->offset);
	if (!handle->buffer) {
		pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		status = PCAP_ERROR;
		goto fail;
	}

	/*
	 * "handle->fd" is a socket, so "select()" and "poll()"
	 * should work on it.
	 */
	 /* Note: pfring_enable_ring() has been moved to pcap_read_packet()
	  * to avoid receiving packets while the bpf filter has not been set yet.
	  * Note this is not a problem for applications lieke tshark using select
	  * because rings get automatically activated on poll too. */
	 handle->selectable_fd = pfring_get_selectable_fd(handlep->ring);
	 return status;

fail:
	pfring_cleanup_linux(handle);
	return status;
}

static void
pfring_pcap_set_appl_name_linux(pcap_t *handle, char *appl_name)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	if (handlep->ring)
		pfring_set_application_name(handlep->ring, appl_name);
}

static void
pfring_pcap_set_cluster(pcap_t *handle, u_int cluster_id)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	if (handlep->ring)
		pfring_set_cluster(handlep->ring, cluster_id, cluster_per_flow);
}

/*
 *  Read at most max_packets from the capture stream and call the callback
 *  for each of them. Returns the number of packets handled or -1 if an
 *  error occured.
 */
static int
pfring_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	/*
	 * Currently, on Linux only one packet is delivered per read,
	 * so we don't loop.
	 */
	return pfring_read_packet(handle, callback, user);
}

static int
pfring_set_datalink_linux(pcap_t *handle, int dlt)
{
	handle->linktype = dlt;
	return 0;
}

/*
 * linux_check_direction()
 *
 * Do checks based on packet direction.
 */
static inline int
linux_check_direction(const pcap_t *handle, const struct sockaddr_ll *sll)
{
	struct pcap_pfring_linux *handlep = handle->priv;

	if (sll->sll_pkttype == PACKET_OUTGOING) {
		/*
		 * Outgoing packet.
		 * If this is from the loopback device, reject it;
		 * we'll see the packet as an incoming packet as well,
		 * and we don't want to see it twice.
		 */
		if (sll->sll_ifindex == handlep->lo_ifindex)
			return 0;

		/*
		 * If the user only wants incoming packets, reject it.
		 */
		if (handle->direction == PCAP_D_IN)
			return 0;
	} else {
		/*
		 * Incoming packet.
		 * If the user only wants outgoing packets, reject it.
		 */
		if (handle->direction == PCAP_D_OUT)
			return 0;
	}
	return 1;
}

/*
 *  Read a packet from the socket calling the handler provided by
 *  the user. Returns the number of packets received or -1 if an
 *  error occured.
 */
static int
pfring_read_packet(pcap_t *handle, pcap_handler callback, u_char *userdata)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	u_char			*bp;
	int			offset;
	struct sockaddr		from;
#if defined(HAVE_PACKET_AUXDATA) && defined(HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI)
	struct iovec		iov;
	struct msghdr		msg;
	struct cmsghdr		*cmsg;
	union {
		struct cmsghdr	cmsg;
		char		buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
	} cmsg_buf;
#else /* defined(HAVE_PACKET_AUXDATA) && defined(HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI) */
	socklen_t		fromlen;
#endif /* defined(HAVE_PACKET_AUXDATA) && defined(HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI) */
	int			packet_len, caplen;
        struct pfring_pkthdr    pcap_header;
        struct bpf_aux_data     aux_data;

	if (handlep->ring) {
		char *packet;
		int wait_for_incoming_packet = (pf_ring_active_poll || (handlep->timeout < 0)) ? 0 : 1;
		int ret = 0;

		if (!handlep->ring->enabled)
			pfring_enable_ring(handlep->ring);

		do {
			if (handle->break_loop) {
				/*
				 * Yes - clear the flag that indicates that it
				 * has, and return -2 as an indication that we
				 * were told to break out of the loop.
				 *
				 * Patch courtesy of Michael Stiller <ms@2scale.net>
				 */
				handle->break_loop = 0;
				return -2;
			}

			pcap_header.ts.tv_sec = 0;
			errno = 0;

			ret = pfring_recv(handlep->ring, (u_char**)&packet, 0, &pcap_header, wait_for_incoming_packet);

			if (ret == 0) {
				if (wait_for_incoming_packet)
					continue;
				return 0; /* non-blocking */
			} else if (ret > 0) {
				bp = packet;
				pcap_header.caplen = min(pcap_header.caplen, handle->bufsize);
				caplen = pcap_header.caplen, packet_len = pcap_header.len;
				if (handle->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO) {
					if (pcap_header.extended_hdr.timestamp_ns) {
						pcap_header.ts.tv_sec  = pcap_header.extended_hdr.timestamp_ns / 1000000000;
						pcap_header.ts.tv_usec = pcap_header.extended_hdr.timestamp_ns % 1000000000;
					} else if (pcap_header.ts.tv_sec == 0)
						clock_gettime(CLOCK_REALTIME, (struct timespec *) &pcap_header.ts);
					else
						pcap_header.ts.tv_usec = pcap_header.ts.tv_usec * 1000;
				} else if (pcap_header.ts.tv_sec == 0)
						gettimeofday((struct timeval *) &pcap_header.ts, NULL);

				break;
			} else {
				if (wait_for_incoming_packet && (errno == EINTR || errno == ENETDOWN))
					continue;
				return -1;
			}
		} while (1);
	}

#if defined(HAVE_PACKET_AUXDATA) && defined(HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI)
	if (handlep->vlan_offset != -1) {
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			struct tpacket_auxdata *aux;
			unsigned int len;
			struct vlan_tag *tag;

			if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata)) ||
			    cmsg->cmsg_level != SOL_PACKET ||
			    cmsg->cmsg_type != PACKET_AUXDATA)
				continue;

			aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
#if defined(TP_STATUS_VLAN_VALID)
			if ((aux->tp_vlan_tci == 0) && !(aux->tp_status & TP_STATUS_VLAN_VALID))
#else
			if (aux->tp_vlan_tci == 0) /* this is ambigious but without the
						TP_STATUS_VLAN_VALID flag, there is
						nothing that we can do */
#endif
				continue;

			len = packet_len > iov.iov_len ? iov.iov_len : packet_len;
			if (len < (unsigned int) handlep->vlan_offset)
				break;

			bp -= VLAN_TAG_LEN;
			memmove(bp, bp + VLAN_TAG_LEN, handlep->vlan_offset);

			tag = (struct vlan_tag *)(bp + handlep->vlan_offset);
			tag->vlan_tpid = htons(VLAN_TPID(aux, aux));
			tag->vlan_tci = htons(aux->tp_vlan_tci);

                        /* store vlan tci to bpf_aux_data struct for userland bpf filter */
#if defined(TP_STATUS_VLAN_VALID)
                        aux_data.vlan_tag = htons(aux->tp_vlan_tci) & 0x0fff;
                        aux_data.vlan_tag_present = (aux->tp_status & TP_STATUS_VLAN_VALID);
#endif
			packet_len += VLAN_TAG_LEN;
		}
	}
#endif /* defined(HAVE_PACKET_AUXDATA) && defined(HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI) */

	/*
	 * XXX: According to the kernel source we should get the real
	 * packet len if calling recvfrom with MSG_TRUNC set. It does
	 * not seem to work here :(, but it is supported by this code
	 * anyway.
	 * To be honest the code RELIES on that feature so this is really
	 * broken with 2.2.x kernels.
	 * I spend a day to figure out what's going on and I found out
	 * that the following is happening:
	 *
	 * The packet comes from a random interface and the packet_rcv
	 * hook is called with a clone of the packet. That code inserts
	 * the packet into the receive queue of the packet socket.
	 * If a filter is attached to that socket that filter is run
	 * first - and there lies the problem. The default filter always
	 * cuts the packet at the snaplen:
	 *
	 * # tcpdump -d
	 * (000) ret      #68
	 *
	 * So the packet filter cuts down the packet. The recvfrom call
	 * says "hey, it's only 68 bytes, it fits into the buffer" with
	 * the result that we don't get the real packet length. This
	 * is valid at least until kernel 2.2.17pre6.
	 *
	 * We currently handle this by making a copy of the filter
	 * program, fixing all "ret" instructions with non-zero
	 * operands to have an operand of MAXIMUM_SNAPLEN so that the
	 * filter doesn't truncate the packet, and supplying that modified
	 * filter to the kernel.
	 */

	caplen = packet_len;
	if (caplen > handle->snapshot)
		caplen = handle->snapshot;

	/* Run the packet filter if not using kernel filter */
	if (handlep->filter_in_userland && handle->fcode.bf_insns) {
		if (bpf_filter_with_aux_data(handle->fcode.bf_insns, bp,
		    packet_len, caplen, &aux_data) == 0) {
			/* rejected by filter */
			return 0;
		}
	}

	/* Fill in our own header data */

        if (!handlep->ring) {

	/* get timestamp for this packet */
#if defined(SIOCGSTAMPNS) && defined(SO_TIMESTAMPNS)
	if (handle->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO) {
		if (ioctl(handle->fd, SIOCGSTAMPNS, &pcap_header.ts) == -1) {
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
					"SIOCGSTAMPNS: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
        } else
#endif
	{
		if (ioctl(handle->fd, SIOCGSTAMP, &pcap_header.ts) == -1) {
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
					"SIOCGSTAMP: %s", pcap_strerror(errno));
			return PCAP_ERROR;
		}
        }

	pcap_header.caplen	= caplen;
	pcap_header.len		= packet_len;

        }

	/*
	 * Count the packet.
	 *
	 * Arguably, we should count them before we check the filter,
	 * as on many other platforms "ps_recv" counts packets
	 * handed to the filter rather than packets that passed
	 * the filter, but if filtering is done in the kernel, we
	 * can't get a count of packets that passed the filter,
	 * and that would mean the meaning of "ps_recv" wouldn't
	 * be the same on all Linux systems.
	 *
	 * XXX - it's not the same on all systems in any case;
	 * ideally, we should have a "get the statistics" call
	 * that supplies more counts and indicates which of them
	 * it supplies, so that we supply a count of packets
	 * handed to the filter only on platforms where that
	 * information is available.
	 *
	 * We count them here even if we can get the packet count
	 * from the kernel, as we can only determine at run time
	 * whether we'll be able to get it from the kernel (if
	 * HAVE_TPACKET_STATS isn't defined, we can't get it from
	 * the kernel, but if it is defined, the library might
	 * have been built with a 2.4 or later kernel, but we
	 * might be running on a 2.2[.x] kernel without Alexey
	 * Kuznetzov's turbopacket patches, and thus the kernel
	 * might not be able to supply those statistics).  We
	 * could, I guess, try, when opening the socket, to get
	 * the statistics, and if we can not increment the count
	 * here, but it's not clear that always incrementing
	 * the count is more expensive than always testing a flag
	 * in memory.
	 *
	 * We keep the count in "handlep->packets_read", and use that
	 * for "ps_recv" if we can't get the statistics from the kernel.
	 * We do that because, if we *can* get the statistics from
	 * the kernel, we use "handlep->stat.ps_recv" and
	 * "handlep->stat.ps_drop" as running counts, as reading the
	 * statistics from the kernel resets the kernel statistics,
	 * and if we directly increment "handlep->stat.ps_recv" here,
	 * that means it will count packets *twice* on systems where
	 * we can get kernel statistics - once here, and once in
	 * pcap_stats_linux().
	 */
	handlep->packets_read++;

	/* Call the user supplied callback function */
	callback(userdata, (struct pcap_pkthdr*) &pcap_header, bp);
	return 1;
}

static int
pfring_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	int ret;

	if (handlep->ring != NULL) {
		if (!handlep->ring->enabled)
			pfring_enable_ring(handlep->ring);
		return pfring_send(handlep->ring, (char*)buf, size, 1 /* FIX: set it to 1 */);
	}

	return (-1);
}

/*
 *  Get the statistics for the given packet capture handle.
 *  Reports the number of dropped packets iff the kernel supports
 *  the PACKET_STATISTICS "getsockopt()" argument (2.4 and later
 *  kernels, and 2.2[.x] kernels with Alexey Kuznetzov's turbopacket
 *  patches); otherwise, that information isn't available, and we lie
 *  and report 0 as the count of dropped packets.
 */
static int
pfring_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_pfring_linux *handlep = handle->priv;
#ifdef HAVE_TPACKET_STATS
#ifdef HAVE_TPACKET3
	/*
	 * For sockets using TPACKET_V1 or TPACKET_V2, the extra
	 * stuff at the end of a struct tpacket_stats_v3 will not
	 * be filled in, and we don't look at it so this is OK even
	 * for those sockets.  In addition, the PF_PACKET socket
	 * code in the kernel only uses the length parameter to
	 * compute how much data to copy out and to indicate how
	 * much data was copied out, so it's OK to base it on the
	 * size of a struct tpacket_stats.
	 *
	 * XXX - it's probably OK, in fact, to just use a
	 * struct tpacket_stats for V3 sockets, as we don't
	 * care about the tp_freeze_q_cnt stat.
	 */
	struct tpacket_stats_v3 kstats;
#else /* HAVE_TPACKET3 */
	struct tpacket_stats kstats;
#endif /* HAVE_TPACKET3 */
	socklen_t len = sizeof (struct tpacket_stats);
#endif /* HAVE_TPACKET_STATS */

	long if_dropped = 0;

	if (handlep->ring != NULL) {
		pfring_stat ring_stats;

		if (pfring_stats(handlep->ring, &ring_stats) == 0) {
			handlep->stat.ps_recv = ring_stats.recv;
				handlep->stat.ps_drop = ring_stats.drop;
			*stats = handlep->stat;
			return 0;
		}
	}

	/*
	 *	To fill in ps_ifdrop, we parse /proc/net/dev for the number
	 */
	if (handle->opt.promisc)
	{
		if_dropped = handlep->proc_dropped;
		handlep->proc_dropped = linux_if_drops(handlep->device);
		handlep->stat.ps_ifdrop += (handlep->proc_dropped - if_dropped);
	}

#ifdef HAVE_TPACKET_STATS
	/*
	 * Try to get the packet counts from the kernel.
	 */
	if (getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS,
			&kstats, &len) > -1) {
		/*
		 * On systems where the PACKET_STATISTICS "getsockopt()"
		 * argument is supported on PF_PACKET sockets:
		 *
		 *	"ps_recv" counts only packets that *passed* the
		 *	filter, not packets that didn't pass the filter.
		 *	This includes packets later dropped because we
		 *	ran out of buffer space.
		 *
		 *	"ps_drop" counts packets dropped because we ran
		 *	out of buffer space.  It doesn't count packets
		 *	dropped by the interface driver.  It counts only
		 *	packets that passed the filter.
		 *
		 *	See above for ps_ifdrop.
		 *
		 *	Both statistics include packets not yet read from
		 *	the kernel by libpcap, and thus not yet seen by
		 *	the application.
		 *
		 * In "linux/net/packet/af_packet.c", at least in the
		 * 2.4.9 kernel, "tp_packets" is incremented for every
		 * packet that passes the packet filter *and* is
		 * successfully queued on the socket; "tp_drops" is
		 * incremented for every packet dropped because there's
		 * not enough free space in the socket buffer.
		 *
		 * When the statistics are returned for a PACKET_STATISTICS
		 * "getsockopt()" call, "tp_drops" is added to "tp_packets",
		 * so that "tp_packets" counts all packets handed to
		 * the PF_PACKET socket, including packets dropped because
		 * there wasn't room on the socket buffer - but not
		 * including packets that didn't pass the filter.
		 *
		 * In the BSD BPF, the count of received packets is
		 * incremented for every packet handed to BPF, regardless
		 * of whether it passed the filter.
		 *
		 * We can't make "pcap_stats()" work the same on both
		 * platforms, but the best approximation is to return
		 * "tp_packets" as the count of packets and "tp_drops"
		 * as the count of drops.
		 *
		 * Keep a running total because each call to
		 *    getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS, ....
		 * resets the counters to zero.
		 */
		handlep->stat.ps_recv += kstats.tp_packets;
		handlep->stat.ps_drop += kstats.tp_drops;
		*stats = handlep->stat;
		return 0;
	}
	else
	{
		/*
		 * If the error was EOPNOTSUPP, fall through, so that
		 * if you build the library on a system with
		 * "struct tpacket_stats" and run it on a system
		 * that doesn't, it works as it does if the library
		 * is built on a system without "struct tpacket_stats".
		 */
		if (errno != EOPNOTSUPP) {
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "pcap_stats: %s", pcap_strerror(errno));
			return -1;
		}
	}
#endif
	/*
	 * On systems where the PACKET_STATISTICS "getsockopt()" argument
	 * is not supported on PF_PACKET sockets:
	 *
	 *	"ps_recv" counts only packets that *passed* the filter,
	 *	not packets that didn't pass the filter.  It does not
	 *	count packets dropped because we ran out of buffer
	 *	space.
	 *
	 *	"ps_drop" is not supported.
	 *
	 *	"ps_ifdrop" is supported. It will return the number
	 *	of drops the interface reports in /proc/net/dev,
	 *	if that is available.
	 *
	 *	"ps_recv" doesn't include packets not yet read from
	 *	the kernel by libpcap.
	 *
	 * We maintain the count of packets processed by libpcap in
	 * "handlep->packets_read", for reasons described in the comment
	 * at the end of pcap_read_packet().  We have no idea how many
	 * packets were dropped by the kernel buffers -- but we know
	 * how many the interface dropped, so we can return that.
	 */

	stats->ps_recv = handlep->packets_read;
	stats->ps_drop = 0;
	stats->ps_ifdrop = handlep->stat.ps_ifdrop;
	return 0;
}


/*
 *  Attach the given BPF code to the packet capture device.
 */
static int
pfring_setfilter_linux_common(pcap_t *handle, struct bpf_program *filter,
    int is_mmapped)
{
	struct pcap_pfring_linux *handlep;
#ifdef SO_ATTACH_FILTER
	struct sock_fprog	fcode;
	int			can_filter_in_kernel;
	int			err = 0;
#endif

	if (!handle)
		return -1;
	if (!filter) {
	        strlcpy(handle->errbuf, "setfilter: No filter specified",
			PCAP_ERRBUF_SIZE);
		return -1;
	}

	handlep = handle->priv;

	if (handlep->ring) {
		if (handlep->bpf_filter && strlen(handlep->bpf_filter) > 0) {
			//printf("pcap_setfilter -> pfring_set_bpf_filter '%s'\n", handlep->bpf_filter ? handlep->bpf_filter : "");
			return pfring_set_bpf_filter(handlep->ring, handlep->bpf_filter);
		}
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(handle, filter) < 0)
		/* install_bpf_program() filled in errbuf */
		return -1;

	/*
	 * Run user level packet filter by default. Will be overriden if
	 * installing a kernel filter succeeds.
	 */
	handlep->filter_in_userland = 1;

	/* Install kernel level filter if possible */

#ifdef SO_ATTACH_FILTER
#ifdef USHRT_MAX
	if (handle->fcode.bf_len > USHRT_MAX) {
		/*
		 * fcode.len is an unsigned short for current kernel.
		 * I have yet to see BPF-Code with that much
		 * instructions but still it is possible. So for the
		 * sake of correctness I added this check.
		 */
		fprintf(stderr, "Warning: Filter too complex for kernel\n");
		fcode.len = 0;
		fcode.filter = NULL;
		can_filter_in_kernel = 0;
	} else
#endif /* USHRT_MAX */
	{
		/*
		 * Oh joy, the Linux kernel uses struct sock_fprog instead
		 * of struct bpf_program and of course the length field is
		 * of different size. Pointed out by Sebastian
		 *
		 * Oh, and we also need to fix it up so that all "ret"
		 * instructions with non-zero operands have MAXIMUM_SNAPLEN
		 * as the operand if we're not capturing in memory-mapped
		 * mode, and so that, if we're in cooked mode, all memory-
		 * reference instructions use special magic offsets in
		 * references to the link-layer header and assume that the
		 * link-layer payload begins at 0; "fix_program()" will do
		 * that.
		 */
		switch (fix_program(handle, &fcode, is_mmapped)) {

		case -1:
		default:
			/*
			 * Fatal error; just quit.
			 * (The "default" case shouldn't happen; we
			 * return -1 for that reason.)
			 */
			return -1;

		case 0:
			/*
			 * The program performed checks that we can't make
			 * work in the kernel.
			 */
			can_filter_in_kernel = 0;
			break;

		case 1:
			/*
			 * We have a filter that'll work in the kernel.
			 */
			can_filter_in_kernel = 1;
			break;
		}
	}

	if (can_filter_in_kernel && handlep->ring != NULL) {
		int if_index;
		if (handlep->ring->zc_device /* ZC: we need to filter in userland as kernel is bypassed */
		    || pfring_get_bound_device_ifindex(handlep->ring, &if_index) != 0 /* not a physical device */)
			can_filter_in_kernel = 0;
	}

	/*
	 * NOTE: at this point, we've set both the "len" and "filter"
	 * fields of "fcode".  As of the 2.6.32.4 kernel, at least,
	 * those are the only members of the "sock_fprog" structure,
	 * so we initialize every member of that structure.
	 *
	 * If there is anything in "fcode" that is not initialized,
	 * it is either a field added in a later kernel, or it's
	 * padding.
	 *
	 * If a new field is added, this code needs to be updated
	 * to set it correctly.
	 *
	 * If there are no other fields, then:
	 *
	 *	if the Linux kernel looks at the padding, it's
	 *	buggy;
	 *
	 *	if the Linux kernel doesn't look at the padding,
	 *	then if some tool complains that we're passing
	 *	uninitialized data to the kernel, then the tool
	 *	is buggy and needs to understand that it's just
	 *	padding.
	 */
	if (can_filter_in_kernel) {
		if ((err = pfring_set_kernel_filter(handle, &fcode)) == 0)
		{
			/*
			 * Installation succeded - using kernel filter,
			 * so userland filtering not needed.
			 */
			handlep->filter_in_userland = 0;
		}
		else if (err == -1)	/* Non-fatal error */
		{
			/*
			 * Print a warning if we weren't able to install
			 * the filter for a reason other than "this kernel
			 * isn't configured to support socket filters.
			 */
			if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
				fprintf(stderr,
				    "Warning: Kernel filter failed: %s\n",
					pcap_strerror(errno));
			}
		}
	}

	/*
	 * If we're not using the kernel filter, get rid of any kernel
	 * filter that might've been there before, e.g. because the
	 * previous filter could work in the kernel, or because some other
	 * code attached a filter to the socket by some means other than
	 * calling "pcap_setfilter()".  Otherwise, the kernel filter may
	 * filter out packets that would pass the new userland filter.
	 */
	if (handlep->filter_in_userland) {
		if (pfring_reset_kernel_filter(handle) == -1) {
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "can't remove kernel filter: %s",
			    pcap_strerror(errno));
			err = -2;	/* fatal error */
		}
	}

	/*
	 * Free up the copy of the filter that was made by "fix_program()".
	 */
	if (fcode.filter != NULL)
		free(fcode.filter);

	if (err == -2)
		/* Fatal error */
		return -1;
#endif /* SO_ATTACH_FILTER */

	return 0;
}

static int
pfring_setfilter_linux(pcap_t *handle, struct bpf_program *filter)
{
	return pfring_setfilter_linux_common(handle, filter, 0);
}


/*
 * Set direction flag: Which packets do we accept on a forwarding
 * single device? IN, OUT or both?
 */
static int
pfring_setdirection_linux(pcap_t *handle, pcap_direction_t d)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	if (handlep->ring != NULL) {
		packet_direction direction;

		switch (d) {
			case PCAP_D_INOUT: direction = rx_and_tx_direction; break;
			case PCAP_D_IN:    direction = rx_only_direction; break;
			case PCAP_D_OUT:   direction = tx_only_direction; break;
		}

		return(pfring_set_direction(handlep->ring, direction));
	}

	/*
	 * We're not using PF_PACKET sockets, so we can't determine
	 * the direction of the packet.
	 */
	pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "Setting direction is not supported on SOCK_PACKET sockets");
	return -1;
}



static void
pfring_cleanup_linux_mmap( pcap_t *handle )
{
	struct pcap_pfring_linux *handlep = handle->priv;

	if (handlep->oneshot_buffer != NULL) {
		free(handlep->oneshot_buffer);
		handlep->oneshot_buffer = NULL;
	}
	pfring_cleanup_linux(handle);
}


static int
pfring_getnonblock_mmap(pcap_t *p)
{
	struct pcap_pfring_linux *handlep = p->priv;

	/* use negative value of timeout to indicate non blocking ops */
	return (handlep->timeout<0);
}

static int
pfring_setnonblock_mmap(pcap_t *p, int nonblock)
{
	struct pcap_pfring_linux *handlep = p->priv;

	/*
	 * Set the file descriptor to non-blocking mode, as we use
	 * it for sending packets.
	 */
	if (pcap_setnonblock_fd(p, nonblock) == -1)
		return -1;

	/*
	 * Map each value to their corresponding negation to
	 * preserve the timeout value provided with pcap_set_timeout.
	 */
	if (nonblock) {
		if (handlep->timeout >= 0) {
			/*
			 * Indicate that we're switching to
			 * non-blocking mode.
			 */
			handlep->timeout = ~handlep->timeout;
		}
	} else {
		if (handlep->timeout < 0) {
			handlep->timeout = ~handlep->timeout;
		}
	}
	return 0;
}

/*
 *  Return the index of the given device name. Fill ebuf and return
 *  -1 on failure.
 */
static int
iface_get_id(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		pcap_snprintf(ebuf, PCAP_ERRBUF_SIZE,
			 "SIOCGIFINDEX: %s", pcap_strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}


/*
 * Don't use the pcap buffer but instead use the one passed by the user.
 * This solution allows multiple threads to read from the same pcap
 * without having to be serialized through a mutex/semaphore.
 */
static const u_char *
pfring_next_pkt(pcap_t *p, struct pcap_pkthdr *h, u_char *buf, u_short bufsize, int *rc)
{
	const u_char *_buf = pcap_next(p, h);
	if (_buf) *rc = 1; else *rc = 0;
	return _buf;
}

#ifdef SO_ATTACH_FILTER
static int
fix_program(pcap_t *handle, struct sock_fprog *fcode, int is_mmapped)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	size_t prog_size;
	register int i;
	register struct bpf_insn *p;
	struct bpf_insn *f;
	int len;

	/*
	 * Make a copy of the filter, and modify that copy if
	 * necessary.
	 */
	prog_size = sizeof(*handle->fcode.bf_insns) * handle->fcode.bf_len;
	len = handle->fcode.bf_len;
	f = (struct bpf_insn *)malloc(prog_size);
	if (f == NULL) {
		pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		return -1;
	}
	memcpy(f, handle->fcode.bf_insns, prog_size);
	fcode->len = len;
	fcode->filter = (struct sock_filter *) f;

	for (i = 0; i < len; ++i) {
		p = &f[i];
		/*
		 * What type of instruction is this?
		 */
		switch (BPF_CLASS(p->code)) {

		case BPF_RET:
			/*
			 * It's a return instruction; are we capturing
			 * in memory-mapped mode?
			 */
			if (!is_mmapped) {
				/*
				 * No; is the snapshot length a constant,
				 * rather than the contents of the
				 * accumulator?
				 */
				if (BPF_MODE(p->code) == BPF_K) {
					/*
					 * Yes - if the value to be returned,
					 * i.e. the snapshot length, is
					 * anything other than 0, make it
					 * MAXIMUM_SNAPLEN, so that the packet
					 * is truncated by "recvfrom()",
					 * not by the filter.
					 *
					 * XXX - there's nothing we can
					 * easily do if it's getting the
					 * value from the accumulator; we'd
					 * have to insert code to force
					 * non-zero values to be
					 * MAXIMUM_SNAPLEN.
					 */
					if (p->k != 0)
						p->k = MAXIMUM_SNAPLEN;
				}
			}
			break;

		case BPF_LD:
		case BPF_LDX:
			/*
			 * It's a load instruction; is it loading
			 * from the packet?
			 */
			switch (BPF_MODE(p->code)) {

			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * Yes; are we in cooked mode?
				 */
				if (handlep->cooked) {
					/*
					 * Yes, so we need to fix this
					 * instruction.
					 */
					if (fix_offset(p) < 0) {
						/*
						 * We failed to do so.
						 * Return 0, so our caller
						 * knows to punt to userland.
						 */
						return 0;
					}
				}
				break;
			}
			break;
		}
	}
	return 1;	/* we succeeded */
}

static int
fix_offset(struct bpf_insn *p)
{
	/*
	 * What's the offset?
	 */
	if (p->k >= SLL_HDR_LEN) {
		/*
		 * It's within the link-layer payload; that starts at an
		 * offset of 0, as far as the kernel packet filter is
		 * concerned, so subtract the length of the link-layer
		 * header.
		 */
		p->k -= SLL_HDR_LEN;
	} else if (p->k == 0) {
		/*
		 * It's the packet type field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PKTTYPE;
	} else if (p->k == 14) {
		/*
		 * It's the protocol field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PROTOCOL;
	} else if ((bpf_int32)(p->k) > 0) {
		/*
		 * It's within the header, but it's not one of those
		 * fields; we can't do that in the kernel, so punt
		 * to userland.
		 */
		return -1;
	}
	return 0;
}

static int
pfring_set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode)
{
	int total_filter_on = 0;
	int save_mode;
	int ret;
	int save_errno;

	struct pcap_pfring_linux *handlep = handle->priv;

	/*
	 * The socket filter code doesn't discard all packets queued
	 * up on the socket when the filter is changed; this means
	 * that packets that don't match the new filter may show up
	 * after the new filter is put onto the socket, if those
	 * packets haven't yet been read.
	 *
	 * This means, for example, that if you do a tcpdump capture
	 * with a filter, the first few packets in the capture might
	 * be packets that wouldn't have passed the filter.
	 *
	 * We therefore discard all packets queued up on the socket
	 * when setting a kernel filter.  (This isn't an issue for
	 * userland filters, as the userland filtering is done after
	 * packets are queued up.)
	 *
	 * To flush those packets, we put the socket in read-only mode,
	 * and read packets from the socket until there are no more to
	 * read.
	 *
	 * In order to keep that from being an infinite loop - i.e.,
	 * to keep more packets from arriving while we're draining
	 * the queue - we put the "total filter", which is a filter
	 * that rejects all packets, onto the socket before draining
	 * the queue.
	 *
	 * This code deliberately ignores any errors, so that you may
	 * get bogus packets if an error occurs, rather than having
	 * the filtering done in userland even if it could have been
	 * done in the kernel.
	 */
	if (setsockopt(handle->fd,
		       (handlep->ring != NULL) ? 0 :
		       SOL_SOCKET,
		       SO_ATTACH_FILTER,
		       &total_fcode, sizeof(total_fcode)) == 0) {
		char drain[1];

		/*
		 * Note that we've put the total filter onto the socket.
		 */
		total_filter_on = 1;
	}

	/*
	 * Now attach the new filter.
	 */
	ret = setsockopt(handle->fd,
		       (handlep->ring != NULL) ? 0 :
			 SOL_SOCKET,
			 SO_ATTACH_FILTER,
			 fcode, sizeof(*fcode));
	if (ret == -1 && total_filter_on) {
		/*
		 * Well, we couldn't set that filter on the socket,
		 * but we could set the total filter on the socket.
		 *
		 * This could, for example, mean that the filter was
		 * too big to put into the kernel, so we'll have to
		 * filter in userland; in any case, we'll be doing
		 * filtering in userland, so we need to remove the
		 * total filter so we see packets.
		 */
		save_errno = errno;

		/*
		 * If this fails, we're really screwed; we have the
		 * total filter on the socket, and it won't come off.
		 * Report it as a fatal error.
		 */
		if (pfring_reset_kernel_filter(handle) == -1) {
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "can't remove kernel total filter: %s",
			    pcap_strerror(errno));
			return -2;	/* fatal error */
		}

		errno = save_errno;
	}
	return ret;
}

static int
pfring_reset_kernel_filter(pcap_t *handle)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	/*
	 * setsockopt() barfs unless it get a dummy parameter.
	 * valgrind whines unless the value is initialized,
	 * as it has no idea that setsockopt() ignores its
	 * parameter.
	 */
	int dummy = 0;

	if (handlep->ring != NULL)
		return 0;

	return setsockopt(handle->fd,
			  SOL_SOCKET,
			  SO_DETACH_FILTER,
			  &dummy, sizeof(dummy));
}
#endif

static u_int32_t
pfring_pcap_get_pfring_id(pcap_t *handle)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	if (handlep->ring == NULL)
		return(0);

	return pfring_get_ring_id(handlep->ring);
}

static int
pfring_pcap_set_master_id(pcap_t *handle, u_int32_t master_id)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	return pfring_set_master_id(handlep->ring, master_id);
}

static int
pfring_pcap_set_master(pcap_t *handle, pcap_t *master)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	struct pcap_pfring_linux *masterp = master->priv;
	return pfring_set_master(handlep->ring, masterp->ring);
}

static int
pfring_pcap_set_application_name(pcap_t *handle, char *name)
{
	struct pcap_pfring_linux *handlep = handle->priv;
	return pfring_set_application_name(handlep->ring, name);
}

static int
pfring_pcap_set_watermark(pcap_t *handle, u_int watermark)
{
	int ret = -1;
	struct pcap_pfring_linux *handlep = handle->priv;

	if (handlep->ring) {
		ret = pfring_set_poll_watermark(handlep->ring, watermark);
	}

	return ret;
}


int pcap_pfring_findalldevs(pcap_if_list_t *devlistp, char *errbuf)
{
        return 0;
}

static
int should_create_pfring_interface(const char *device)
{
	return
      		getenv("PCAP_PF_RING_ACTIVE_POLL") 	 		||
   		getenv("PCAP_PF_RING_DNA_RSS")  			||
   		getenv("PCAP_PF_RING_ZC_RSS")				||
   		getenv("PCAP_PF_RING_STRIP_HW_TIMESTAMP") 		||
   		getenv("PCAP_PF_RING_HW_TIMESTAMP") 			||
   		getenv("PCAP_PF_RING_RECV_ONLY") 			||
   		getenv("PCAP_PF_RING_CLUSTER_ID")			||
        	getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW")		||
        	getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_2_TUPLE") 	||
        	getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE") 	||
        	getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_TCP_5_TUPLE") ||
        	getenv("PCAP_PF_RING_USE_CLUSTER_PER_FLOW_5_TUPLE") 	||
 		getenv("PCAP_PF_RING_APPNAME") 				||
   		getenv("PCAP_PF_RING_RSS_REHASH") 			||
        	!strncmp(device, "pfring:", 7) 				||
		!strncmp(device, "zc:", 3);
}


pcap_t *
pcap_pfring_create(const char *device, char *ebuf, int *is_ours)
{
        pcap_t *p;

        *is_ours = should_create_pfring_interface(device);
        if (!*is_ours)
                return NULL;
        p = pcap_create_common(ebuf, sizeof (struct pcap_pfring_linux));
        if (p == NULL)
                return NULL;

        p->activate_op = pfring_activate_linux;
	return p;
}



