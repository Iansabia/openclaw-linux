/*
 * kelp_netfilter.c — Netfilter hook for network-aware AI
 *
 * Hooks into the LOCAL_OUT chain to log/inspect outbound connections.
 * Events are made available to userspace via /proc/kelp/netfilter
 * and can be analyzed by the gateway daemon.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "kelp_internal.h"

/* Recent connection log — circular buffer of recent network events */
#define NF_LOG_SIZE 256

struct nf_event {
    __be32   src_ip;
    __be32   dst_ip;
    __be16   src_port;
    __be16   dst_port;
    uint8_t  protocol;   /* IPPROTO_TCP, IPPROTO_UDP */
    uint64_t timestamp;  /* ktime in nanoseconds */
};

static struct nf_event nf_log[NF_LOG_SIZE];
static int nf_log_pos;
static DEFINE_SPINLOCK(nf_log_lock);

/* Netfilter hook struct */
static struct nf_hook_ops nf_hook_ops;

/*
 * Netfilter hook callback — called for each outbound IPv4 packet.
 *
 * Currently logs TCP/UDP connections. In production, this would
 * feed events to the gateway daemon for AI-powered analysis.
 */
static unsigned int kelp_nf_hook(void *priv,
                                   struct sk_buff *skb,
                                   const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct kelp_kstats *st = kelp_get_stats();
    struct nf_event *ev;
    unsigned long flags;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    st->netfilter_packets++;

    /* Only log TCP and UDP */
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    spin_lock_irqsave(&nf_log_lock, flags);
    ev = &nf_log[nf_log_pos];
    ev->src_ip = iph->saddr;
    ev->dst_ip = iph->daddr;
    ev->protocol = iph->protocol;
    ev->timestamp = ktime_get_ns();

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (tcph) {
            ev->src_port = tcph->source;
            ev->dst_port = tcph->dest;

            /* Log new connections (SYN packets) at debug level */
            if (tcph->syn && !tcph->ack && kelp_get_log_level() >= 2) {
                pr_info("kelp: TCP SYN %pI4:%d -> %pI4:%d\n",
                        &iph->saddr, ntohs(tcph->source),
                        &iph->daddr, ntohs(tcph->dest));
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (udph) {
            ev->src_port = udph->source;
            ev->dst_port = udph->dest;
        }
    }

    nf_log_pos = (nf_log_pos + 1) % NF_LOG_SIZE;
    spin_unlock_irqrestore(&nf_log_lock, flags);

    /* Always accept — we're monitoring, not filtering */
    return NF_ACCEPT;
}

/* Get netfilter log for procfs */
int kelp_nf_get_recent(char *buf, size_t buf_size)
{
    unsigned long flags;
    int pos = 0;
    int i, idx;

    spin_lock_irqsave(&nf_log_lock, flags);

    /* Show last 20 events */
    for (i = 0; i < 20 && i < NF_LOG_SIZE; i++) {
        idx = (nf_log_pos - 1 - i + NF_LOG_SIZE) % NF_LOG_SIZE;
        struct nf_event *ev = &nf_log[idx];

        if (ev->timestamp == 0) continue; /* Empty slot */

        pos += snprintf(buf + pos, buf_size - (size_t)pos,
                        "  %pI4:%d -> %pI4:%d %s\n",
                        &ev->src_ip, ntohs(ev->src_port),
                        &ev->dst_ip, ntohs(ev->dst_port),
                        ev->protocol == IPPROTO_TCP ? "TCP" : "UDP");

        if ((size_t)pos >= buf_size - 1) break;
    }

    spin_unlock_irqrestore(&nf_log_lock, flags);
    return pos;
}

int kelp_netfilter_init(void)
{
    memset(nf_log, 0, sizeof(nf_log));
    nf_log_pos = 0;

    nf_hook_ops.hook     = kelp_nf_hook;
    nf_hook_ops.pf       = PF_INET;
    nf_hook_ops.hooknum  = NF_INET_LOCAL_OUT;
    nf_hook_ops.priority = NF_IP_PRI_LAST;

    int ret = nf_register_net_hook(&init_net, &nf_hook_ops);
    if (ret < 0) {
        pr_err("kelp: failed to register netfilter hook: %d\n", ret);
        return ret;
    }

    pr_info("kelp: netfilter hook registered (LOCAL_OUT)\n");
    return 0;
}

void kelp_netfilter_exit(void)
{
    nf_unregister_net_hook(&init_net, &nf_hook_ops);
    pr_info("kelp: netfilter hook unregistered\n");
}
