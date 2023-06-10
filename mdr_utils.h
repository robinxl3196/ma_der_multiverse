#ifndef _MDR_UTILS_H_
#define _MDR_UTILS_H_

#include <linux/preempt.h>
#include <linux/slab.h>

#define MAC_ADDR_LEN    6
#define IP_ADDR_LEN     4
#define IP6_ADDR_LEN    16

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

#endif /* _MDR_UTILS_H_ */