#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>	/* Needed for the macros */
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <asm/highmem.h>
#include <asm/tlbflush.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <asm/page.h>
#include <crypto/aes.h>
#include <linux/time.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>

#include "blk_crypto.h"

#define MAX_APP_NAME_SIZE TASK_COMM_LEN
#define APP_LIST_SIZE 20

/* List of apps to be:
 * - encrypted during suspend (IF is_encryption_enabled() [see suspend.c])
 * - unfrozen on pin unlock (when "thaw" is written to read_proc)
 */
extern char * app_list[APP_LIST_SIZE];

// = {
    // "ndroid.contacts",
    // "droid.apps.maps",
	// "twitter.android",
	// "android.youtube",
	// "com.vevo",
	// "flipboard.app",
	// "m.android.phone",
	// "ovio.angrybirds",
	// ".candycrushsaga",
	// ".android.chrome",
	// "ndroid.contacts",
	// "NULL"};

char* getPathName(struct file *file);
bool to_encrypt(struct task_struct *task);
void encrypt_task_start(void);
void encrypt_task_finish(const char* label);
int encrypt_task_and_update_pte(void);
void encrypt_vma(struct mm_struct *mm, struct vm_area_struct *vma, int * dma_pgs);
void encrypt_task(struct task_struct *task, bool encrypt);
void encrypt_kernel_stack(struct task_struct* task, bool encrypt);
void decrypt_dma(struct task_struct* task);
void decrypt_vma(struct mm_struct *mm, struct vm_area_struct *vma, int * pgs_decrypted);
void updateVmallocPte(bool encrypt);
void updateTaskPte(struct task_struct *task, bool encrypt);
void updateVmaPte(struct mm_struct *mm, struct vm_area_struct *vma, bool encrypt);
unsigned long vir_to_phy(struct mm_struct *mm, unsigned long vir);
struct page* vir_to_page(struct mm_struct *mm, unsigned long vir);
pte_t* vir_to_pte(struct mm_struct *mm, unsigned long vir);
pte_t* virt_to_pte_k(const unsigned long virt);

