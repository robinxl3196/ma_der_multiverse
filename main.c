#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/if_ether.h>
#include <uapi/linux/netfilter_bridge.h>

/* This module was developed in kernel version 5.15.0 */

static unsigned int br_forward_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ethhdr *eth_header = eth_hdr(skb);

    if (eth_header == NULL)
    {
        goto FINALLY;
    }

    printk("src: %02X%02X%02X%02X%02X%02X, dst: %02X%02X%02X%02X%02X%02X\n",
           eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
           eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5],
           eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
           eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);

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
    printk(KERN_INFO "[%s] Enter\n", __FUNCTION__);

    res = nf_register_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
    if (res < 0)
    {
        printk(KERN_INFO "[%s] Failed to register netfilter hooks with errno %d\n", __FUNCTION__, res);
        return -ENODEV;
    }

    return 0;
}

static void __exit ma_der_exit(void)
{
    printk(KERN_INFO "[%s] Enter\n", __FUNCTION__);
    nf_unregister_net_hooks(&init_net, nf_hooks, ARRAY_SIZE(nf_hooks));
}

module_init(ma_der_init);
module_exit(ma_der_exit);

MODULE_LICENSE("GPL");
