#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic/atomic-instrumented.h>
#include <linux/delay.h>
#include "mdr_utils.h"
#include "mdr_flow.h"
#include "mdr_flow_table.h"

#define FLOW_TABLE_BUCKET_COUNT         32
#define FLOW_TABLE_FLUSH_PREIOD_MSECS   60*1000
#define FLOW_TIMEOUT_THRESHOLD_MSECS    10*60*1000

enum
{
    FLOW_STATE_MONITOR = 0,
    FLOW_STATE_GARBAGE,
};

struct flow_control_block
{
    struct mdr_flow_key flow_key;
    struct mdr_flow_info flow_info;
    struct list_head list_node;

    atomic_t use_count;
    u32 last_use_time;

    u32 bucket_offset;
    u8 flow_state;
    u8 padding[3];
};

struct flow_table
{
    spinlock_t bucket_locks[FLOW_TABLE_BUCKET_COUNT];
    struct list_head bucket_heads[FLOW_TABLE_BUCKET_COUNT];
    atomic_t flow_block_count;
    u32 next_flush_timing;
    u8 padding[4];
} g_flow_table;

// FNV-1a hash
static inline u32 hash_func(u8 *data, int data_len)
{
    u32 hash = 2166136261;
    for (data_len -= 1; data_len >= 0; data_len--)
    {
        hash ^= data[data_len];
        hash *= 16777619;
    }
    return hash;
}

/// @brief      Calculate flow table bucket offset by flow 5-tuple key
/// @param key  Pointer to the key object
static inline u32 get_bucket_offset(struct mdr_flow_key *key)
{
    return hash_func((u8*)key, sizeof(struct mdr_flow_key)) % FLOW_TABLE_BUCKET_COUNT;
}

/// @brief          Create a new flow block with specified key
/// @param key      Pointer to the flow key object
/// @return         Pointer to the new flow block object, or NULL otherwise
static struct flow_control_block *create_flow_block(struct mdr_flow_key *key)
{
    struct flow_control_block *flow_block = mdr_malloc(sizeof(struct flow_control_block));
    if (flow_block == NULL)
    {
        return NULL;
    }

    memset(flow_block, 0, sizeof(struct flow_control_block));
    memcpy(&flow_block->flow_key, key, sizeof(struct mdr_flow_key));
    INIT_LIST_HEAD(&flow_block->list_node);
    mdr_flow_init(&flow_block->flow_info);
    flow_block->use_count = (atomic_t) ATOMIC_INIT(0);
    atomic_inc(&g_flow_table.flow_block_count);

    return flow_block;
}

/// @brief              Delete a flow block object
/// @param flow_block   Pointer to the flow block object
void delete_flow_block(struct flow_control_block *flow_block)
{
    mdr_flow_clear(&flow_block->flow_info);
    mdr_free(flow_block);
    atomic_dec(&g_flow_table.flow_block_count);
}

/// @brief          Find a the target flow block with specified key and bucket offset
/// @param key      Pointer to the flow key object
/// @param offset   The bucket offset
/// @return         Pointer to the existed flow block object, or NULL otherwise
static struct flow_control_block *find_flow_block(struct mdr_flow_key *key, u32 offset)
{
    struct list_head *iterator;
    struct flow_control_block *flow_block;

    list_for_each(iterator, &g_flow_table.bucket_heads[offset])
    {
        flow_block = list_entry(iterator, struct flow_control_block, list_node);
        if (memcmp(key, &flow_block->flow_key, sizeof(struct mdr_flow_key)) == 0)
        {
            break;
        }
    }
    /* Not exist */
    if (list_is_head(iterator, &g_flow_table.bucket_heads[offset]))
    {
        return NULL;
    }

    return flow_block;
}

/// @brief              Increase the use count of a flow block object
/// @param flow_block   Pointer to the flow block
static void get_flow_block(struct flow_control_block *flow_block)
{
    flow_block->last_use_time = get_current_msecs();
    atomic_inc(&flow_block->use_count);
}

/// @brief              Decrement the use count of a flow block object
/// @param flow_block   Pointer tp the flow block
static void put_flow_block(struct flow_control_block *flow_block)
{
    if (atomic_dec_return(&flow_block->use_count) == 0)
    {
        delete_flow_block(flow_block);
    }
}

/// @brief              Insert a flow block into table
/// @param flow_block   Pointer to the target flow block object
/// @param offset       The offset of bucket in the table
static void insert_flow_block_to_table(struct flow_control_block *flow_block, u32 offset)
{
    flow_block->flow_state = FLOW_STATE_MONITOR;
    flow_block->bucket_offset = offset;
    list_add(&flow_block->list_node, &g_flow_table.bucket_heads[offset]);
    get_flow_block(flow_block);
}

/// @brief              Remove a flow block from the flow table
/// @param flow_block   Pointer to the flow block object
static void remove_flow_block_from_table(struct flow_control_block *flow_block)
{
    flow_block->flow_state = FLOW_STATE_GARBAGE;
    list_del(&flow_block->list_node);
    put_flow_block(flow_block);
}

/// @brief Remove flow block from flow table if it timeouts
static void check_flush_timing(void)
{
    static atomic_t mutual_exclusive = ATOMIC_INIT(0);

    struct list_head *iterator;
    struct flow_control_block *flow_block;
    u32 current_time;
    int offset;

    if (atomic_xchg(&mutual_exclusive, 1))
    {
        return;
    }

    current_time = get_current_msecs();
    if (current_time < g_flow_table.next_flush_timing)
    {
        goto FINALLY;
    }
    g_flow_table.next_flush_timing = current_time + FLOW_TABLE_FLUSH_PREIOD_MSECS;

    for (offset = 0; offset < FLOW_TABLE_BUCKET_COUNT; offset++)
    {
        spin_lock_bh(&g_flow_table.bucket_locks[offset]);
        list_for_each(iterator, &g_flow_table.bucket_heads[offset])
        {
            flow_block = list_entry(iterator, struct flow_control_block, list_node);
            if (current_time > flow_block->last_use_time + FLOW_TIMEOUT_THRESHOLD_MSECS)
            {
                remove_flow_block_from_table(flow_block);
            }
        }
        spin_unlock_bh(&g_flow_table.bucket_locks[offset]);
    }

FINALLY:
    atomic_set(&mutual_exclusive, 0);
}

struct mdr_flow_info * mdr_flow_table_get(struct mdr_flow_key *key)
{
    u32 offset = get_bucket_offset(key);
    struct flow_control_block *flow_block;

    check_flush_timing();

    spin_lock_bh(&g_flow_table.bucket_locks[offset]);

    flow_block = find_flow_block(key, offset);
    if (flow_block == NULL)
    {
        flow_block = create_flow_block(key);
        if (flow_block)
        {
            insert_flow_block_to_table(flow_block, offset);
        }
    }

    if (flow_block)
    {
        get_flow_block(flow_block);
    }

    spin_unlock_bh(&g_flow_table.bucket_locks[offset]);

    return flow_block ? &flow_block->flow_info : NULL;
}

struct mdr_flow_info * mdr_flow_table_get_new(struct mdr_flow_key *key)
{
    u32 offset = get_bucket_offset(key);
    struct flow_control_block *flow_block;

    check_flush_timing();

    spin_lock_bh(&g_flow_table.bucket_locks[offset]);

    flow_block = find_flow_block(key, offset);
    if (flow_block)
    {
        remove_flow_block_from_table(flow_block);
    }

    flow_block = create_flow_block(key);
    if (flow_block)
    {
        insert_flow_block_to_table(flow_block, offset);
        get_flow_block(flow_block);
    }

    spin_unlock_bh(&g_flow_table.bucket_locks[offset]);

    return flow_block ? &flow_block->flow_info : NULL;
}

void mdr_flow_table_put(struct mdr_flow_info *flow)
{
    struct flow_control_block *flow_block = container_of(flow, struct flow_control_block, flow_info);
    put_flow_block(flow_block);
}

void mdr_flow_table_init(void)
{
    int i;

    memset(&g_flow_table, 0, sizeof(struct flow_table));

    for (i = 0; i < FLOW_TABLE_BUCKET_COUNT; i++)
    {
        spin_lock_init(&g_flow_table.bucket_locks[i]);
        INIT_LIST_HEAD(&g_flow_table.bucket_heads[i]);
    }

    g_flow_table.flow_block_count = (atomic_t) ATOMIC_INIT(0);
}

void mdr_flow_table_exit(void)
{
    struct list_head *iterator;
    struct flow_control_block *flow_block;
    int i;

    for (i = FLOW_TABLE_BUCKET_COUNT - 1; i >= 0; i--)
    {
        spin_lock_bh(&g_flow_table.bucket_locks[i]);
        list_for_each(iterator, &g_flow_table.bucket_heads[i])
        {
            flow_block = list_entry(iterator, struct flow_control_block, list_node);
            remove_flow_block_from_table(flow_block);
        }
        spin_unlock_bh(&g_flow_table.bucket_locks[i]);
    }

    for (i = 0; atomic_read(&g_flow_table.flow_block_count) && i < 10; mdelay(100), i++);
}

void mdr_gen_flow_key(struct mdr_flow_key *key, int inet_ver,
                      u8 *addr0, u8 *addr1, u16 port0, u16 port1, u8 protocol)
{
    if (inet_ver != INET_VER_4 && inet_ver != INET_VER_6)
    {
        return;
    }

    if (port0 < port1)
    {
        u8 *addr_tmp = addr0;
        u16 port_tmp = port0;

        addr0 = addr1;
        addr1 = addr_tmp;

        port0 = port1;
        port1 = port_tmp;
    }

    memset(key, 0, sizeof(struct mdr_flow_key));
    memcpy(key->addr0, addr0, inet_ver == INET_VER_4 ? INET_VER_4 : INET_VER_6);
    memcpy(key->addr1, addr1, inet_ver == INET_VER_4 ? INET_VER_4 : INET_VER_6);
    key->port0 = port0;
    key->port1 = port1;
    key->protocol = protocol;
    key->inet_ver = inet_ver;
}