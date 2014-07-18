/* Wrappers around dynamic memory allocation functions to allocate from secure memory 
 * instead of regular RAM.
 *
 * This memory should be harder to physically extract (e.g. via a cold-boot attack).
 *
 * e.g. 
 * on ARM, this allocates from TCM.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_CRYPTO_SECURE_ALLOC

#ifdef CONFIG_ARM

#include <linux/tcm_heap.h>
#include <asm/pgtable.h>

static inline void * __tcm_alloc(size_t size, gfp_t gfp_mask)
{
    void * ptr = tcm_code_alloc(size);
	if (ptr != NULL && (gfp_mask & __GFP_ZERO)) {
        memset(ptr, 0, size);
    }
    return ptr;
}

#if 0
inline unsigned long crypto_alloc_page(gfp_t gfp_mask)
{
    return (unsigned long)__tcm_alloc(PAGE_SIZE, gfp_mask);
}
#define crypto_alloc_percpu(type) \
	(typeof(type) __percpu *)crypto_kmalloc(sizeof(type)*nr_cpu_ids)

#define crypto_per_cpu_ptr(ptr, cpu) \
    (ptr[cpu])
#define crypto_this_cpu_ptr \
    (ptr[smp_processor_id()])
#define crypto_free_percpu crypto_kmalloc_free
#endif

#define crypto_alloc_page alloc_page
#define crypto_alloc_percpu  alloc_percpu
#define crypto_per_cpu_ptr per_cpu_ptr
#define crypto_this_cpu_ptr this_cpu_ptr
#define crypto_free_percpu free_percpu

static int is_tcm_code_addr(void * addr) 
{
    return
        (unsigned long)addr >= (unsigned long)get_tcm_code_offset() &&
        (unsigned long)addr < (unsigned long)get_tcm_code_offset() + get_tcm_code_size();
}

void *crypto_kmalloc(size_t size, gfp_t flags)
{
    if (tcm_code_initialized()) {
        return __tcm_alloc(size, flags);
    } else {
        return kmalloc(size, flags);
    }

    /* return kmalloc(size, flags); */
}

void *crypto__get_free_page(gfp_t flags)
{
    if (tcm_code_initialized()) {
        return __tcm_alloc(PAGE_SIZE, flags);
    } else {
        return kmalloc(PAGE_SIZE, flags);
    }
}
EXPORT_SYMBOL(crypto__get_free_page);

inline void *crypto_kzalloc(size_t size, gfp_t flags)
{
    return crypto_kmalloc(size, flags | __GFP_ZERO);
}

#if 0
void *crypto_vmalloc(unsigned long size)
{
    return __tcm_alloc(size, GFP_KERNEL | __GFP_HIGHMEM);
}

void *crypto_vzalloc(unsigned long size)
{
	return __tcm_alloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO);
}
#endif

/* #define crypto_kfree kfree */

void crypto_kfree(void * ptr)
{
    if (tcm_code_initialized() && is_tcm_code_addr(ptr)) {
        tcm_code_free(ptr);
    } else {
        kfree(ptr);
    }
}

void crypto_kzfree(void *ptr)
{
    if (tcm_code_initialized() && is_tcm_code_addr(ptr)) {
        tcm_code_kzfree(ptr);
    } else {
        kzfree(ptr);
    }
}
EXPORT_SYMBOL(crypto_kzfree);

void * crypto_vmalloc(unsigned long size)
{
    if (tcm_code_initialized()) {
        return __tcm_alloc(size, 0);
    } else {
        return vmalloc(size);
    }
}
EXPORT_SYMBOL(crypto_vmalloc);

void *crypto_vzalloc(unsigned long size)
{
    if (tcm_code_initialized()) {
        return __tcm_alloc(size, __GFP_ZERO);
    } else {
        return vzalloc(size);
    }
}
EXPORT_SYMBOL(crypto_vzalloc);

void crypto_vfree(void * ptr)
{
    if (tcm_code_initialized() && is_tcm_code_addr(ptr)) {
        tcm_code_free(ptr);
    } else {
        vfree(ptr);
    }
}
EXPORT_SYMBOL(crypto_vfree);

// TODO: define remaining free functions, replace kzalloc and try just kmalloc

#endif /* CONFIG_ARM */

#endif /* CONFIG_CRYPTO_SECURE_ALLOC */
