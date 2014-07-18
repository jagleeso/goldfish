#ifndef SECURE_ALLOC_H
#define SECURE_ALLOC_H

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

#ifdef CONFIG_CRYPTO_SECURE_ALLOC

#ifdef CONFIG_ARM

#if 0
inline unsigned long crypto_alloc_page(gfp_t gfp_mask);
#define crypto_alloc_percpu(type) \
	(typeof(type) __percpu *)crypto_kmalloc(sizeof(type)*nr_cpu_ids)

#define crypto_per_cpu_ptr(ptr, cpu) \
    (ptr[cpu])
#define crypto_this_cpu_ptr \
    (ptr[smp_processor_id()])
#define crypto_free_percpu crypto_kmalloc_free
void *crypto_vmalloc(unsigned long size);
void *crypto_vzalloc(unsigned long size);
#endif

#define crypto_alloc_page alloc_page
#define crypto_alloc_percpu  alloc_percpu
#define crypto_per_cpu_ptr per_cpu_ptr
#define crypto_this_cpu_ptr this_cpu_ptr
#define crypto_free_percpu free_percpu

void *crypto_kmalloc(size_t size, gfp_t flags);
void *crypto_kzalloc(size_t size, gfp_t flags);
void crypto_kfree(void * ptr);
void crypto_kzfree(void * ptr);
void crypto_vfree(void * ptr);
void *crypto_vzalloc(unsigned long size);

// TODO: define remaining free functions, replace kzalloc and try just kmalloc

#else /* CONFIG_ARM */
#error "This architecture doesn't have secure memory."
#endif /* CONFIG_ARM */

#else /* CONFIG_CRYPTO_SECURE_ALLOC */

#define crypto_alloc_page alloc_page
#define crypto_alloc_percpu  alloc_percpu
#define crypto_per_cpu_ptr per_cpu_ptr
#define crypto_this_cpu_ptr this_cpu_ptr
#define crypto_free_percpu free_percpu
#define crypto_kmalloc kmalloc
#define crypto_kfree kfree
#define crypto_kzfree kzfree
#define crypto_kzalloc kzalloc
#define crypto_vmalloc vmalloc
#define crypto_vzalloc vzalloc
#define crypto_vfree vfree

#endif /* CONFIG_CRYPTO_SECURE_ALLOC */

#endif /* end of include guard: SECURE_ALLOC_H */
