#ifndef _MDR_PACKET_INFO_H_
#define _MDR_PACKET_INFO_H_

#include <linux/list.h>
#include "mdr_utils.h"


/* Forward declaration */
struct sk_buff;

struct ethernet_info
{
    u8 src_mac[MAC_ADDR_LEN];
    u8 dst_mac[MAC_ADDR_LEN];
    u16 eth_type;
    u8 padding[2];
};

struct internet_info
{
    u8 src_ip[IP_ADDR_LEN];
    u8 dst_ip[IP_ADDR_LEN];
    u8 protocol;
    u8 padding[7];
};

struct transport_info
{
    u16 src_port;
    u16 dst_port;
    u8 syn: 1;
    u8 rst: 1;
    u8 ack: 1;
    u8 fin: 1;
    u8 unused_bits: 4;
    u8 padding[3];
};

struct packet_info
{
    struct ethernet_info  ether_info;
    struct internet_info  inter_info;
    struct transport_info trans_info;

    char *payload;
    u32 payload_len;
    u8 padding[4];
};

/* Use to buffer a whole packet from L2 to L7 */
struct packet_raw_data
{
    struct list_head list_node;
    u32 pkt_data_len;
    u8 padding[4];
    u8 pkt_data[];
};

enum DECODE_PACKET_RESULT
{
    DECODE_ETHERNET_FAILED  = -1,
    DECODE_INTERNET_FAILED  = -2,
    DECODE_TRANSPORT_FAILED = -3,
    DECODE_SUCCESS          = 0,
};

/// @brief              Decode packet from L2 to L4
/// @param pkt_info     Buffer for decoding results
/// @param data         Pointer to data (lineared)
/// @param data_len     Legnth of data
/// @return             DECODE_PACKET_RESULT
int mdr_decode_packet(struct packet_info *pkt_info, unsigned char *data, u32 data_len);

/// @brief              Generate a packet_raw_data object to buffer target data
/// @param data         Data to be buffered
/// @param data_len     Length of data
/// @return             Pointer to the packet_raw_data object, or NULL otherwise
struct packet_raw_data * mdr_gen_pkt_raw_data(unsigned char *data, u32 data_len);

#endif /* _MDR_PACKET_INFO_H_ */