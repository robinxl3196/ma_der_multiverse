#ifndef _MDR_FLOW_H_
#define _MDR_FLOW_H_

#include <linux/list.h>
#include <linux/spinlock_types.h>

/* Forward declaration */
struct packet_raw_data;

enum
{
    INET_VER_4 = 4,
    INET_VER_6 = 6,
};

struct mdr_flow_key
{
    u8 addr0[IP6_ADDR_LEN];
    u8 addr1[IP6_ADDR_LEN];
    u16 port0;
    u16 port1;
    u8 protocol;
    u8 inet_ver;
    u8 padding[2];
};

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

/// @brief          Generate flow key, that is 5-tuple
/// @param key      The buffer to put result
/// @param inet_ver INET_VER_4 or INET_VER_6
/// @param addr0    Pointer to the first address data
/// @param addr1    Pointer to the second address data
/// @param port0    The first port number
/// @param port1    The second port number
/// @param protocol The osi4 internet protocol number
void mdr_gen_flow_key(struct mdr_flow_key *key, int inet_ver, u8 *addr0, u8 *addr1, u16 port0, u16 port1, u8 protocol);

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