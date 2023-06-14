#include <linux/spinlock.h>

#include "mdr_packet_info.h"
#include "mdr_utils.h"
#include "mdr_flow.h"

void mdr_flow_init(struct mdr_flow_info *flow)
{
    memset(flow, 0, sizeof(struct mdr_flow_info));
    INIT_LIST_HEAD(&flow->buffered_packets);
    spin_lock_init(&flow->lock);
}

void mdr_flow_add_pkt_statistic(struct mdr_flow_info *flow, u32 payload_len)
{
    spin_lock_bh(&flow->lock);
    flow->total_packets_count += 1;
    flow->total_payload_count += payload_len;
    spin_unlock_bh(&flow->lock);
}

void mdr_flow_enqueue_packet(struct mdr_flow_info *flow, struct packet_raw_data *pkt)
{
    spin_lock_bh(&flow->lock);
    list_add_tail(&pkt->list_node, &flow->buffered_packets);
    spin_unlock_bh(&flow->lock);
}

void mdr_flow_clear(struct mdr_flow_info *flow)
{
    struct packet_raw_data *pkt;

    spin_lock_bh(&flow->lock);

    while (!list_empty(&flow->buffered_packets))
    {
        pkt = container_of(flow->buffered_packets.next, struct packet_raw_data, list_node);
        list_del(&pkt->list_node);
        mdr_free(pkt);
    }

    spin_unlock_bh(&flow->lock);
}