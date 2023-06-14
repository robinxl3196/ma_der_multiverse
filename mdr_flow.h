#ifndef _MDR_FLOW_H_
#define _MDR_FLOW_H_

#include <linux/list.h>
#include <linux/spinlock_types.h>

/* Forward declaration */
struct packet_raw_data;

struct mdr_flow_info
{
    struct list_head buffered_packets;
    u32 total_payload_count;    // application layer in bytes
    u32 total_packets_count;
    spinlock_t lock;
};

/// @brief      Initialize a flow object
/// @param flow Pointer to the target flow object
void mdr_flow_init(struct mdr_flow_info *flow);

/// @brief              Update flow statistics by a payload length of a packet
/// @param flow         Pointer to the target flow object
/// @param payload_len  The packet length to update
void mdr_flow_add_pkt_statistic(struct mdr_flow_info *flow, u32 payload_len);

/// @brief          Buffer a packet
/// @param flow     Pointer to the target flow object
/// @param pkt      Pointer to the packet object to buffer
void mdr_flow_enqueue_packet(struct mdr_flow_info *flow, struct packet_raw_data *pkt);

/// @brief          Clear all data in a flow object
/// @param flow     Pointer to the flow object
void mdr_flow_clear(struct mdr_flow_info *flow);

#endif /* _MDR_FLOW_H_ */