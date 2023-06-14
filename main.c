#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <uapi/linux/netfilter_bridge.h>

#include "mdr_packet_info.h"
#include "mdr_flow.h"
#include "mdr_flow_table.h"

/* This module was developed in kernel version 5.15.0 */

static unsigned int br_forward_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct packet_info pkt_info;
    unsigned char *skb_mac, *skb_tail;
    int result;

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

    mdr_flow_table_init();

    res = nf_register_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
    if (res < 0)
    {
        pr_info("[%s] Failed to register netfilter hooks with errno %d\n", __FUNCTION__, res);
        goto REGISTER_NF_HOOK_FAILED;
    }

    return 0;

REGISTER_NF_HOOK_FAILED:
    mdr_flow_table_exit();

    return -ENODEV;
}

static void __exit ma_der_exit(void)
{
    pr_info("[%s] Enter\n", __FUNCTION__);
    nf_unregister_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
    mdr_flow_table_exit();
}

module_init(ma_der_init);
module_exit(ma_der_exit);

MODULE_LICENSE("ฅ•ω•ฅ");
