#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/genalloc.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <asm/mach/map.h>

#include <crypto/aes.h>

#ifdef CONFIG_ARCH_MSM
#include <mach/peripheral-loader.h>
struct subsys_desc;
int dsps_shutdown(const struct subsys_desc *subsys);
#endif

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

void * get_tcm_code_offset(void)
{
    return (void *) tcm_code_offset;
}
EXPORT_SYMBOL(get_tcm_code_offset);

unsigned long get_tcm_code_size(void)
{
    return tcm_code_size;
}
EXPORT_SYMBOL(get_tcm_code_size);

/* Allocate some physically contiguous pages.
 *
 * 160*1K = 4096 * 40
 * ceil(log2(40)) = 6
 */
#define TCM_SIZE_ORDER 6
static struct gen_pool * tcm_code_pool = NULL;

#define SIZE_IDX(vaddr) \
    (( (vaddr - tcm_code_offset)/sizeof(unsigned long) )*sizeof(unsigned long))
#define GET_SIZE(vaddr) \
    (alloc_sizes[SIZE_IDX(vaddr)])
#define SET_SIZE(vaddr, size) \
    alloc_sizes[SIZE_IDX(vaddr)] = size
static unsigned long * alloc_sizes;

static DEFINE_SPINLOCK(tcm_init_lock);
static int initialized = 0;
static int initializing = 0;

static int __init tcm_code_pool_init(void)
{
    int ret;

    unsigned long flags;
    spin_lock_irqsave(&tcm_init_lock, flags);

#ifndef CONFIG_DEBUG_TCM_HEAP
    /* tcm_code_offset = UL(0XFA01B000); */
    tcm_code_offset = UL(0XFA01C000);
    tcm_code_size = (160*SZ_1K) - ( UL(0XFA01C000) - UL(0XFA01B000) );
#else
	tcm_code_offset = __get_free_pages(GFP_KERNEL | __GFP_ZERO,
					TCM_SIZE_ORDER);
    // technically its 2^6 * 4096 = 256K, just pool 160K though.
    tcm_code_size = (160*SZ_1K);
#endif

    alloc_sizes = kzalloc(tcm_code_size, GFP_KERNEL);
    if (!alloc_sizes) {
        ret = -ENOMEM;
        goto fail_alloc_sizes;
    }

	/* Set up malloc pool, 2^2 = 4 byte granularity.
     * Pages and cache line alignments don't matter in TCM.
	 */
    BUG_ON(tcm_code_pool != NULL);
	tcm_code_pool = gen_pool_create(2, -1);
	if (!tcm_code_pool) {
		ret = -ENOMEM;
        goto fail_tcm_code_pool;
    }

	ret = gen_pool_add(tcm_code_pool, (unsigned long)tcm_code_offset, tcm_code_size, -1);
	WARN_ON(ret < 0);
    if (ret) {
        goto fail_gen_pool_add;
    }

	MY_PRINTK("i.MX TCM_CODE pool: %lu KB@0x%p\n", tcm_code_size / 1024, (void *)tcm_code_offset);

	spin_unlock_irqrestore(&tcm_init_lock, flags);

	return 0;

fail_gen_pool_add:
    gen_pool_destroy(tcm_code_pool);
fail_tcm_code_pool:
    kfree(alloc_sizes);
fail_alloc_sizes:
    free_pages(tcm_code_offset, TCM_SIZE_ORDER);
	spin_unlock_irqrestore(&tcm_init_lock, flags);
    return ret;

}

static int init_tcm_tboxes(void);
static void disable_dsps(void);
static int init_tcm_global_cwq(void);

/* During boot, we setup the gen_pool struct, but we can't use it yet since DSPS 
 * hasn't been disabled. So, more intialization will happen on module load (when we 
 * can disable DSPS).
 */
/* #define NO_TCM */
int late_tcm_code_setup(void)
{
    int ret = 0;

    disable_dsps();

    unsigned long flags;
    spin_lock_irqsave(&tcm_init_lock, flags);
    if (initializing || initialized) {
        goto done_initializing;
    }
    initializing = 1;
	spin_unlock_irqrestore(&tcm_init_lock, flags);

    if (!initialized) { 

        /* Do any one-time intialization.
         */
        ret = init_tcm_tboxes();
        if (ret) {
            MY_PRINTK("%s:%i @ %s:\n" 
                   "  init_tcm_boxes FAILED.\n"
                , __FILE__, __LINE__, __func__
                );
            goto fail_init_tcm_tboxes;
        }

#ifndef NO_TCM
        ret = init_tcm_global_cwq();
        if (ret) {
            MY_PRINTK("%s:%i @ %s:\n" 
                   "  init_tcm_global_cwq FAILED.\n"
                , __FILE__, __LINE__, __func__
                );
            goto fail_init_tcm_global_cwq;
        }
#endif

        initialized = 1;
    }

fail_init_tcm_global_cwq:
    /* TODO: revert tboxes to static ones */
fail_init_tcm_tboxes:
    spin_lock_irqsave(&tcm_init_lock, flags);
    initializing = 0;
done_initializing:
	spin_unlock_irqrestore(&tcm_init_lock, flags);

    return ret;

}
EXPORT_SYMBOL(late_tcm_code_setup);

static int init_tcm_global_cwq(void)
{
    int ret = 0;

    ret = init_gcwq(WORK_TCM);
    if (ret)
        return ret;

    ret = init_initial_worker(WORK_TCM);
    if (ret)
        return ret;

	system_tcm_wq = alloc_workqueue("events_tcm", WQ_TCM,
					    WQ_UNBOUND_MAX_ACTIVE);
    BUG_ON(!system_tcm_wq);

    return ret;
}

/* We can start allocating from the TCM once DSPS is disabled.
     */
void disable_dsps(void)
{
#ifdef CONFIG_ARCH_MSM
    dsps_shutdown(NULL);
#endif
}
EXPORT_SYMBOL(disable_dsps);

int tcm_code_initialized(void)
{
    unsigned long flags;
    spin_lock_irqsave(&tcm_init_lock, flags);
    int _initialized = initialized;
	spin_unlock_irqrestore(&tcm_init_lock, flags);
    return _initialized;
}
EXPORT_SYMBOL(tcm_code_initialized);

static void tcm_code_pool_destroy(void)
{
    if (tcm_code_pool) {
        gen_pool_destroy(tcm_code_pool);
    }
}

/* Can't allocate anything smaller than this, since we need to store the allocation 
 * size at word aligned indices into alloc_sizes.
 */
#define alloc_assertions \
    BUG_ON(len < sizeof(unsigned long)); \
    BUG_ON(len > tcm_code_size); \
    BUG_ON(tcm_code_pool == NULL); \

/*
 * Allocate a chunk of TCM memory
 */
void *tcm_code_alloc(size_t len)
{
	unsigned long vaddr;

    alloc_assertions;

    MY_PRINTK("%s:%i @ %s:\n" 
           "  len = %lu\n"
        , __FILE__, __LINE__, __func__
        , (unsigned long) len
        );
    dump_stack();

	vaddr = gen_pool_alloc(tcm_code_pool, len);
	if (!vaddr) {
        WARN(1, "TCM heap is full!");
		return NULL;
    }

    SET_SIZE(vaddr, len);

	return (void *) vaddr;
}
EXPORT_SYMBOL(tcm_code_alloc);

void *tcm_code_alloc_aligned(size_t len, unsigned long alignment_order)
{
	unsigned long vaddr;

    alloc_assertions;

    MY_PRINTK("%s:%i @ %s:\n" 
           "  len = %lu\n"
           "  alignment_order = %lu\n"
        , __FILE__, __LINE__, __func__
        , (unsigned long) len
        , alignment_order
        );
    dump_stack();

	vaddr = gen_pool_alloc_aligned(tcm_code_pool, len, alignment_order);
	if (!vaddr) {
        WARN(1, "TCM heap is full!");
		return NULL;
    }

    SET_SIZE(vaddr, len);

	return (void *) vaddr;
}
EXPORT_SYMBOL(tcm_code_alloc_aligned);

/*
 * Free a chunk of TCM memory
 */
void tcm_code_free(void *addr)
{

    size_t len = GET_SIZE((unsigned long)addr);

    BUG_ON(len == 0);
    BUG_ON((unsigned long)addr < (unsigned long)tcm_code_offset);
    BUG_ON((unsigned long)addr > (unsigned long)tcm_code_offset + tcm_code_size - sizeof(unsigned long));

    MY_PRINTK("%s:%i @ %s:\n" 
           "  addr = 0x%p\n"
           "  len = %lu\n"
        , __FILE__, __LINE__, __func__
        , addr
        , (unsigned long) len
        );
    dump_stack();

	gen_pool_free(tcm_code_pool, (unsigned long) addr, len);
}
EXPORT_SYMBOL(tcm_code_free);

void tcm_code_kzfree(void *addr)
{
    size_t len = GET_SIZE((unsigned long)addr);
	memset(addr, 0, len);
    tcm_code_free(addr);
}
EXPORT_SYMBOL(tcm_code_kzfree);

/* Copy table to TCM allocated memory, then adjust the pointer to point to it.
 */
static int copy_box(const u32 *** static_table)
{
    u32 ** tcm_table = tcm_code_alloc(4 * sizeof(u32*));
    if (!tcm_table) {
        return -ENOMEM;
    }
    memset(tcm_table, 0, 4 * sizeof(u32*));
    int i, j;
    for (i = 0; i < 4; i++) {
        tcm_table[i] = tcm_code_alloc(256 * sizeof(u32));
        if (!tcm_table[i]) {
            goto cleanup;
        }
        for (j = 0; j < 256; j++) {
            tcm_table[i][j] = (*static_table)[i][j];
        }
    }
    /* *static_table = (const u32 **) tcm_table; */
    return 0;
cleanup:
    for (i = 0; i < 4; i++) {
        if (tcm_table[i]) {
            tcm_code_free((void *)tcm_table[i]);
        }
    }
    return -ENOMEM;
}
static int init_tcm_tboxes(void)
{

    int ret = 0;
#define TRY_COPY_BOX(box) \
    const u32 ** __static_##box = box; \
    ret = copy_box(&box); \
    if (ret) { \
        goto fail_##box; \
    } \

    TRY_COPY_BOX(crypto_ft_tab);
    TRY_COPY_BOX(crypto_fl_tab);
    TRY_COPY_BOX(crypto_il_tab);
    TRY_COPY_BOX(crypto_it_tab);

    return 0;

    int i, j;
#define REVERT_BOX(box) \
    for (i = 0; i < 4; i++) { \
        if (box[i]) { \
            tcm_code_free((void *)box[i]); \
        } \
    } \
    tcm_code_free((void *)box); \
    crypto_it_tab = __static_##box; \

fail_crypto_it_tab:
    REVERT_BOX(crypto_it_tab);
fail_crypto_il_tab:
    REVERT_BOX(crypto_il_tab);
fail_crypto_fl_tab:
    REVERT_BOX(crypto_fl_tab);
fail_crypto_ft_tab:
    return ret;

}

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
