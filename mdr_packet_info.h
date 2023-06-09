#ifndef _MDR_PACKET_INFO_H_
#define _MDR_PACKET_INFO_H_

#include "mdr_utils.h"

#define MAC_ADDR_LEN    6
#define IP_ADDR_LEN     4

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
    u8 padding[3];
};

struct transport_info
{
    u16 src_port;
    u16 dst_port;
};

struct packet_info
{
    struct ethernet_info  ether_info;
    struct internet_info  inter_info;
    struct transport_info trans_info;

    u32 payload_len;
    char *payload;
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

#endif /* _MDR_PACKET_INFO_H_ */