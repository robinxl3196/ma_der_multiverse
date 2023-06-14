#ifndef _MDR_FLOW_TABLE_H_
#define _MDR_FLOW_TABLE_H_

/* Forward declaration */
struct mdr_flow_info;

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

/// @brief          Generate flow key, that is 5-tuple
/// @param key      The buffer to put result
/// @param inet_ver INET_VER_4 or INET_VER_6
/// @param addr0    Pointer to the first address data
/// @param addr1    Pointer to the second address data
/// @param port0    The first port number
/// @param port1    The second port number
/// @param protocol The osi4 internet protocol number
void mdr_gen_flow_key(struct mdr_flow_key *key, int inet_ver, u8 *addr0, u8 *addr1, u16 port0, u16 port1, u8 protocol);

/// @brief  Initialize flow table structure
void mdr_flow_table_init(void);

/// @brief  Clear flow table structure
void mdr_flow_table_exit(void);

struct mdr_flow_info *mdr_flow_table_get(struct mdr_flow_key *key);

struct mdr_flow_info *mdr_flow_table_get_new(struct mdr_flow_key *key);

void mdr_flow_table_put(struct mdr_flow_info *flow);

#endif /* _MDR_FLOW_TABLE_H_ */