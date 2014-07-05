#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/genalloc.h>
#include <linux/ioport.h>
#include <asm/mach/map.h>

/* Hardcore Nexus 4 TCM addresses here for now since dynamically detecting them (in tcm.c) 
 * fails because of TrustZone.
 *
 * Check for free mapped virtual memory region setup in Nexus 4's static configuration of io 
 * regions:
 * 
 * $KERN/arch/arm/mach-msm/include/mach/msm_iomap-8064.h:118
 *   APQ8064_IRAM_PHYS, APQ8064_IRAM_SIZE
 *
 * $KERN/arch/arm/mach-msm/include/mach/msm_iomap.h:95
 *   MSM_IRAM_BASE
 *
 * $KERN/arch/arm/mach-msm/io.c:289
 *   static struct map_desc apq8064_io_desc[] __initdata = {
 *       ...
 *   	MSM_CHIP_DEVICE(IRAM, APQ8064),
 *       ...
 *   };
 */

#define TCM_CODE_OFFSET	
#define TCM_CODE_SIZE (160*SZ_1K)
#define TCM_CODE_PHYS (0x12000000)

static unsigned long tcm_code_offset;
static unsigned long tcm_code_size; 

static void * get_tcm_code_offset(void)
{
    return (void *) tcm_code_offset;
}
EXPORT_SYMBOL(get_tcm_code_offset);

static struct gen_pool * tcm_code_pool = NULL;
static int __init tcm_code_pool_init(void)
{
    int ret;

#ifndef CONFIG_DEBUG_TCM_HEAP
    /* tcm_code_offset = UL(0XFA01B000); */
    /* Make it 8K aligned?
     */
    tcm_code_offset = UL(0XFA01C000);
    tcm_code_size = (160*SZ_1K);
#else
    /* Allocate some physically contiguous pages.
     *
     * 160*1K = 4096 * 40
     * ceil(log2(40)) = 6
     */
	tcm_code_offset = __get_free_pages(GFP_KERNEL | __GFP_ZERO,
					6);
    // technically its 2^6 * 4096 = 256K, just pool 160K though.
    tcm_code_size = (160*SZ_1K);
#endif

	/* Set up malloc pool, 2^2 = 4 byte granularity.
     * Pages and cache line alignments don't matter in TCM.
	 */
    BUG_ON(tcm_code_pool != NULL);
	tcm_code_pool = gen_pool_create(2, -1);
	if (!tcm_code_pool)
		return -ENOMEM;

	ret = gen_pool_add(tcm_code_pool, (unsigned long)tcm_code_offset, tcm_code_size, -1);
	WARN_ON(ret < 0);
    if (ret)
        return ret;

	MY_PRINTK("i.MX TCM_CODE pool: %lu KB@0x%p\n", tcm_code_size / 1024, (void *)tcm_code_offset);

	return 0;
}

static void tcm_code_pool_destroy(void)
{
    if (tcm_code_pool) {
        gen_pool_destroy(tcm_code_pool);
    }
}

/*
 * Allocate a chunk of TCM memory
 */
void *tcm_code_alloc(size_t len)
{
	unsigned long vaddr;

    BUG_ON(tcm_code_pool == NULL);

	vaddr = gen_pool_alloc(tcm_code_pool, len);
	if (!vaddr)
		return NULL;

	return (void *) vaddr;
}
EXPORT_SYMBOL(tcm_code_alloc);

void *tcm_code_alloc_aligned(size_t len, unsigned long alignment_order)
{
	unsigned long vaddr;

    BUG_ON(tcm_code_pool == NULL);

	vaddr = gen_pool_alloc_aligned(tcm_code_pool, len, alignment_order);
	if (!vaddr)
		return NULL;

	return (void *) vaddr;
}
EXPORT_SYMBOL(tcm_code_alloc_aligned);

/*
 * Free a chunk of TCM memory
 */
void tcm_code_free(void *addr, size_t len)
{
	gen_pool_free(tcm_code_pool, (unsigned long) addr, len);
}
EXPORT_SYMBOL(tcm_code_free);

int __init setup_tcm_memory(void)
{
    int ret;

    ret = tcm_code_pool_init();
    if (ret) {
        goto failure;
    }

    return 0;

failure:
    return ret;
}

core_initcall(setup_tcm_memory);
