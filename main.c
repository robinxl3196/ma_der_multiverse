#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <uapi/linux/netfilter_bridge.h>

#include "mdr_packet_info.h"

/* This module was developed in kernel version 5.15.0 */

static unsigned int br_forward_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct packet_info pkt_info;
    unsigned char *skb_mac, *skb_tail;
    int result;
    u8 one_ip[4] = {1, 1, 1, 1};

    /*
        skb->len        := linear + non-linear
        skb->data_len   := non-linear
        TODO: Not doing linearize, since it takes much time to write data
    */

    skb_mac = skb_mac_header(skb);
    skb_tail = skb_tail_pointer(skb);

    if ((uintptr_t)skb_mac >= (uintptr_t)skb_tail)
    {
        goto FINALLY;
    }

    result = mdr_decode_packet(&pkt_info, skb_mac, (uintptr_t)skb_tail - (uintptr_t)skb_mac);
    if (result != DECODE_SUCCESS)
    {
        goto FINALLY;
    }

    if (memcmp(pkt_info.inter_info.src_ip, one_ip, 4) == 0 ||
        memcmp(pkt_info.inter_info.dst_ip, one_ip, 4) == 0)
    {
        pr_info("mac_src:%02X%02X%02X%02X%02X%02X -> dst_src:%02X%02X%02X%02X%02X%02X\n"
                "    ip_src:%u.%u.%u.%u -> ip_dst: %u.%u.%u.%u\n"
                "        port_src:%u -> port_dst:%u\n",
                pkt_info.ether_info.src_mac[0], pkt_info.ether_info.src_mac[1],
                pkt_info.ether_info.src_mac[2], pkt_info.ether_info.src_mac[3],
                pkt_info.ether_info.src_mac[4], pkt_info.ether_info.src_mac[5],
                pkt_info.ether_info.dst_mac[0], pkt_info.ether_info.dst_mac[1],
                pkt_info.ether_info.dst_mac[2], pkt_info.ether_info.dst_mac[3],
                pkt_info.ether_info.dst_mac[4], pkt_info.ether_info.dst_mac[5],
                pkt_info.inter_info.src_ip[0], pkt_info.inter_info.src_ip[1],
                pkt_info.inter_info.src_ip[2], pkt_info.inter_info.src_ip[3],
                pkt_info.inter_info.dst_ip[0], pkt_info.inter_info.dst_ip[1],
                pkt_info.inter_info.dst_ip[2], pkt_info.inter_info.dst_ip[3],
                pkt_info.trans_info.src_port, pkt_info.trans_info.dst_port);
    }

FINALLY:

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_hooks[] =
{
    {
        .hook       = br_forward_hook_func,
        .pf         = NFPROTO_BRIDGE,
        .hooknum    = NF_BR_FORWARD,
        .priority   = NF_BR_PRI_BRNF + 1,
    },
};

static int __init ma_der_init(void)
{
    int res = 0;
    pr_info("[%s] Enter\n", __FUNCTION__);

    res = nf_register_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
    if (res < 0)
    {
        pr_info("[%s] Failed to register netfilter hooks with errno %d\n", __FUNCTION__, res);
        return -ENODEV;
    }

    return 0;
}

static void __exit ma_der_exit(void)
{
    pr_info("[%s] Enter\n", __FUNCTION__);
    nf_unregister_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
}

module_init(ma_der_init);
module_exit(ma_der_exit);

MODULE_LICENSE("ฅ•ω•ฅ");
