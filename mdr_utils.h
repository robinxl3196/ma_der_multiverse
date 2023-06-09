#ifndef _MDR_UTILS_H_
#define _MDR_UTILS_H_

#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/jiffies.h>

#define MAC_ADDR_LEN    6
#define IP_ADDR_LEN     4
#define IP6_ADDR_LEN    16

#define SUCCESS 0
#define FAILURE 1

/// @brief      Wrap function for malloc in kernel space
/// @param size The size of requested memory space
/// @return     NULL if failed
static inline void* mdr_malloc(u32 size)
{
    return in_interrupt() ? kmalloc(size, GFP_ATOMIC) : kmalloc(size, GFP_KERNEL);
}

/// @brief      Wrap function for release memory in kernel space
/// @param ptr  Pointer to memory block to be freed
static inline void mdr_free(void *ptr)
{
    kfree(ptr);
}

/// @brief      Get current millisecond
/// @return     Millisecond since boot up
static inline u32 get_current_msecs(void)
{
    return jiffies_to_msecs(jiffies - INITIAL_JIFFIES);
}

#endif /* _MDR_UTILS_H_ */