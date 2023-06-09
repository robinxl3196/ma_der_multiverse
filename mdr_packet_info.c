#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>

#include "mdr_packet_info.h"
#include "mdr_utils.h"

#define ETH_HDR_MIN_LEN         14
#define INTERNET_HDR_MIN_LEN    20
#define TCP_HDR_MIN_LEN         20


/// @brief          Decode ethernet header
/// @param eth_info Buffer of results
/// @param data     Pointer to header start
/// @param data_len Available length of data
/// @return         Offset of the next header, 0 if failed to parse
static u32 decode_eth(struct ethernet_info *eth_info, unsigned char *data, u32 data_len)
{
    if (data_len < ETH_HDR_MIN_LEN)
    {
        return 0;
    }

    memcpy(eth_info->dst_mac, data, MAC_ADDR_LEN);
    memcpy(eth_info->src_mac, data + 6, MAC_ADDR_LEN);
    eth_info->eth_type = ntohs(*(u16*)(data + 12));

    if (eth_info->eth_type != ETH_P_IP)
    {
        return 0;
    }

    switch (eth_info->eth_type)
    {
    case ETH_P_IP:
    /* fallthrough */
    case ETH_P_IPV6:
        return ETH_HDR_MIN_LEN;
    default:
    }

    return 0;
}

/// @brief          Decode IPv4 header
/// @param in_info  Buffer of results
/// @param data     Pointer to header start
/// @param data_len Available length of data
/// @return         Offset of the next header, 0 if failed to parse
static u32 decode_ip(struct internet_info *in_info, unsigned char *data, u32 data_len)
{
    /* RFC 791
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    if (data_len < INTERNET_HDR_MIN_LEN)
    {
        return 0;
    }

    // check version
    if ((data[0]) >> 4 != 4)
    {
        return 0;
    }

    // Not checking total length due to the packet may not be linearize
    // Not checking fragmentation

    in_info->protocol = data[9];
    memcpy(&in_info->src_ip, data + 12, IP_ADDR_LEN);
    memcpy(&in_info->dst_ip, data + 16, IP_ADDR_LEN);

    // count header length
    if ((data[0] & 0x0f) * 4 > data_len)
    {
        return 0;
    }

    return (data[0] & 0x0f) * 4;
}

/// @brief              Decode TCP header
/// @param trans_info   Buffer of results
/// @param data         Pointer to header start
/// @param data_len     Available length of data
/// @return             Offset of the next header, 0 if failed to parse
static u32 decode_tcp(struct transport_info *trans_info, unsigned char *data, u32 data_len)
{

    /* RFC 793
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Acknowledgment Number                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Data |           |U|A|P|R|S|F|                               |
        | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        |       |           |G|K|H|T|N|N|                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |         Urgent Pointer        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             data                              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */

    if (data_len < TCP_HDR_MIN_LEN)
    {
        return 0;
    }

    trans_info->src_port = ntohs(*(u16*)data);
    trans_info->dst_port = ntohs(*(u16*)(data + 2));

    // shift (>>) is prior than bitwise and (&)
    trans_info->fin = data[13] >> 0 & 1;
    trans_info->syn = data[13] >> 1 & 1;
    trans_info->rst = data[13] >> 2 & 1;
    trans_info->ack = data[13] >> 4 & 1;

    // check header length
    if ((data[12] >> 4) * 4 > data_len)
    {
        return 0;
    }

    return (data[12] >> 4) * 4;
}

int mdr_decode_packet(struct packet_info *pkt_info, unsigned char *data, u32 data_len)
{
    u32 next_offset = 0;
    int ret = DECODE_ETHERNET_FAILED;

    memset(pkt_info, 0, sizeof(struct packet_info));

    next_offset = decode_eth(&pkt_info->ether_info, data, data_len);
    if (next_offset == 0 || next_offset > data_len)
    {
        ret = DECODE_ETHERNET_FAILED;
        goto FINALLY;
    }

    data += next_offset;
    data_len -= next_offset;

    switch (pkt_info->ether_info.eth_type)
    {
    case ETH_P_IP:
        next_offset = decode_ip(&pkt_info->inter_info, data, data_len);
        break;
    default:
        ret = DECODE_INTERNET_FAILED;
        goto FINALLY;
    }

    if (next_offset == 0 || next_offset > data_len)
    {
        ret = DECODE_INTERNET_FAILED;
        goto FINALLY;
    }

    data += next_offset;
    data_len -= next_offset;

    switch (pkt_info->inter_info.protocol)
    {
    case IPPROTO_TCP:
        next_offset = decode_tcp(&pkt_info->trans_info, data, data_len);
        break;
    default:
        ret = DECODE_TRANSPORT_FAILED;
        goto FINALLY;
    }

    if (next_offset == 0 || next_offset > data_len)
    {
        ret = DECODE_TRANSPORT_FAILED;
        goto FINALLY;
    }

    data += next_offset;
    data_len -= next_offset;

    pkt_info->payload = data;
    pkt_info->payload_len = data_len;

    ret = DECODE_SUCCESS;

FINALLY:
    return ret;
}