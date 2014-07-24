#include <asm/tlbflush.h>
#include <linux/blk_crypto.h>
#include <linux/export.h>
#include <linux/mem_encrypt.h>
#include <linux/module.h>

static DEFINE_SPINLOCK(lock);
static unsigned long count_page_encrypted = 0;
static unsigned long count_page_encrypted_all = 0;
static unsigned long count_page_resident = 0;
static unsigned long count_page_resident_all = 0;

#define MAX(X, Y) ((X) >= (Y) ? (X) : (Y))

static int initialized = 0;
struct blkcipher_desc encrypt_desc;

static struct timeval t0;
static struct timeval t1;

static DEFINE_SPINLOCK(app_list_lock);
/* static int is_app_list_initialized = 0; */

char * app_list[APP_LIST_SIZE];

unsigned int app_list_count(void)
{
	unsigned int i;

    for (i = 0; i < APP_LIST_SIZE && app_list[i][0]; i++) {
    }
	return i;
}

static char app_list_block[APP_LIST_SIZE*TASK_COMM_LEN];
void init_app_list(void) 
{
    int i;
    memset(app_list_block, 0, sizeof(char)*APP_LIST_SIZE*TASK_COMM_LEN);
    for (i = 0; i < APP_LIST_SIZE; i++) {
        app_list[i] = &app_list_block[TASK_COMM_LEN*i];
    }
}

void print_app_list(void)
{
    int i;
    printk("App list:\n");
    for (i = 0; i < APP_LIST_SIZE && app_list[i][0]; i++) {
        printk("    %s\n", app_list[i]);
    }
}

#define MAX_PROC 1024
/* Set app list using a "_" separated list of task->comm names
 */
void set_app_list(const char * proc) 
{
    int app_list_idx;
	unsigned long flags;

    // start/end of single proc name in proc
    int i, j;
    int k;

	spin_lock_irqsave(&app_list_lock, flags);

    init_app_list();

    i = 0;
    app_list_idx = 0;
    while (i < strlen(proc)) {
        j = i;
        while (proc[j] != '\0' && proc[j] != '_') {
            j += 1;
        }

        BUG_ON(app_list_idx >= APP_LIST_SIZE);

        int comm_len = j - i;
        /* We only want the last 15 non-null characters of the comm name.
         * (i.e. a comm name can only have at most 15 non-null characters, the last character is always \0).
         */
        int start = i + MAX(0, (comm_len + 1) - TASK_COMM_LEN);
        for (k = start; k < j; k++) {
            BUG_ON(k - start > TASK_COMM_LEN);
            app_list[app_list_idx][k - start] = proc[k];
        }

        i = j + 1;
        app_list_idx += 1;
    }

    print_app_list();

    spin_unlock_irqrestore(&app_list_lock, flags);

}
EXPORT_SYMBOL(set_app_list);

bool to_encrypt(struct task_struct *task)
{
	int i;
    bool retval = false;
	unsigned long flags;
	spin_lock_irqsave(&app_list_lock, flags);
    for (i = 0; i < APP_LIST_SIZE && app_list[i][0]; i++) {
		if (strcmp(app_list[i], task->comm) == 0) {
            retval = true;
            goto DONE;
        }
	}
DONE:
    spin_unlock_irqrestore(&app_list_lock, flags);
	return retval;
}
EXPORT_SYMBOL(to_encrypt);

void encrypt_task_start(void)
{
	do_gettimeofday(&t0);
}

void encrypt_task_finish(const char* label)
{
	long int diff;
	do_gettimeofday(&t1);
	diff = (t1.tv_usec + 1000000 * t1.tv_sec) - (t0.tv_usec + 1000000 * t0.tv_sec);
	printk("PM: %s took %ld.%03ld seconds\n", label, diff / 1000000, diff / 1000);
}

void do_init(void) {

	unsigned long flags;
    int ret;
	spin_lock_irqsave(&lock, flags);
    if (initialized) {
        spin_unlock_irqrestore(&lock, flags);
        return;
    }
    spin_unlock_irqrestore(&lock, flags);

	ret = init_blkcipher_desc(&encrypt_desc);
	BUG_ON(ret < 0);

	spin_lock_irqsave(&lock, flags);
    initialized = 1;
    spin_unlock_irqrestore(&lock, flags);

}

void __init mem_encrypt_init(void) 
{
    printk("HELLO, INIT MEM_ENCRYPT\n");
    init_app_list();
    set_app_list("com.android.browser");
    /* do_init(); */
}

int encrypt_task_and_update_pte(void)
{	
	struct task_struct *task;
	bool ret;
	bool task_found = false;
	unsigned long flags;
	unsigned int task_encrypted = 0;
	unsigned int task_to_encrypt = 0; 

	encrypt_task_start();

	printk("%s\n", __func__ );

	ret = init_blkcipher_desc(&encrypt_desc);
	if (ret < 0) {
		printk("init_blkciper_desc failed\n");
		return false;
	}

	spin_lock_irqsave(&lock, flags);
	task_to_encrypt = app_list_count();
	for_each_process(task) {
		if (!to_encrypt(task))
			continue;

		printk("Task %s (pid = %d) found\n",task->comm, task_pid_nr(task));
		encrypt_task(task);
		task->flags |= PF_ENCRYPTED;
		task_found = true;
		if (++task_encrypted >= task_to_encrypt)
			break;
	}

	if (task_found) {
        printk("encrypt all tasks finished, sum %luMB, %luMB mem encrypted\n\n", count_page_resident_all * 4 /1024,  count_page_encrypted_all * 4 / 1024);
        print_page_stats(1);
    } else {
        printk("Task not found\n");
    }

	updateVmallocPte();

	for_each_process(task) {
		updateTaskPte(task);
	} 
    if (task_found) {
        encrypt_task_finish("encrypt task");
    }
	spin_unlock_irqrestore(&lock, flags);
	crypto_free_blkcipher(encrypt_desc.tfm);

	return 0;
}

void encrypt_task(struct task_struct *task)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int i;
    int dma_pgs = 0;

    do_init();

	count_page_encrypted = 0;
	count_page_resident = 0;

	mm = task->mm;
	if (!mm) {
		return;
	}

#ifdef DEBUG
	printk("mm exists\n");
	printk("map_count is %d\n, this is the number of vma", mm->map_count);
	printk("start_code %lx, end_code %lx\n", mm->start_code, mm->end_code);
	printk("start_data %lx, end_data %lx\n", mm->start_data, mm->end_data);
	printk("start_brk %lx, brk %lx\n", mm->start_brk, mm->brk);
	printk("start_stack %lx\n", mm->start_stack);
#endif

	vma = mm->mmap;

	for (i = 0; i < mm->map_count && vma != NULL; i++) {
		encrypt_vma(mm, vma, &dma_pgs);
		vma = vma->vm_next;
	}

	printk("encrypt task %s finished, resident mem %luMB, encrypted mem %luMB\n\n", task->comm, count_page_resident *4 /1024, count_page_encrypted * 4 / 1024);
	count_page_encrypted_all += count_page_encrypted;
	count_page_resident_all += count_page_resident;
    printk("> DMA encrypted for %s: %i pages (%i MB), decrypt vma\n", task->comm, dma_pgs, dma_pgs*4/1024);
}
EXPORT_SYMBOL_GPL(encrypt_task);

void encrypt_vma(struct mm_struct *mm, struct vm_area_struct *vma, int * dma_pgs)
{
	struct page* pg;
	pte_t *ptep, pte;
	long unsigned int pg_count = 0;
	unsigned long linear_add;
	unsigned i;
#ifdef DEBUG
	static unsigned long total_pg_count = 0;
#endif
	//calculate the number of pages in the vma
	pg_count = (vma->vm_end-vma->vm_start)/PAGE_SIZE;
#ifdef DEBUG
	total_pg_count += pg_count;
	printk("total pg count is %lu \n", total_pg_count);
#endif
	//printk("vma exists, vm_start=0x%lx, vm_end=0x%lx, pages=%lx\n", vma->vm_start, vma->vm_end, pg_count);
	
	linear_add = vma->vm_start;
	for (i = 0; i < pg_count; i++, linear_add += PAGE_SIZE) {
		pg = vir_to_page(mm, linear_add);
		ptep = vir_to_pte(mm, linear_add);
		if (pg == NULL || ptep == NULL) {
			continue;
		}
		count_page_resident++;

		if (vma->vm_flags & VM_RESERVED)
			goto encrypt;

		if (vma->vm_flags & VM_SHARED || vma->vm_flags & VM_MAYSHARE)
			continue;

		if (page_count(pg) > 1)
			continue;

		if (page_mapcount(pg) == 0) {
			continue;
		}

encrypt:
		if (encrypt_page(pg)) {
            if (vma->vm_flags & VM_RESERVED && dma_pgs != NULL) { 
                *dma_pgs += 1;
            }
			ptep_test_and_clear_young(vma, linear_add, ptep);
			pte = pte_mkencrypted(*ptep);
			set_pte_at(mm, linear_add, ptep, pte);
			flush_tlb_page(vma, linear_add);
			count_page_encrypted++;
		}
	}
}

void decrypt_dma(struct task_struct* task)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int i;
    int pgs_decrypted = 0;

	mm = task->mm;
	if (!mm) {
		return;
	}

    /* BUG: 
     * Sometimes mm is invalid (ff000000, != NULL).
     * Not sure what's causing this...
     */
	vma = mm->mmap;

	for (i = 0; i < mm->map_count && vma != NULL; i++) {
		if (vma->vm_flags & VM_RESERVED) {
			//printk("%s %s VM_RESERVED, decrypt vma\n", __func__, task->comm);
			decrypt_vma(mm, vma, &pgs_decrypted);
		}
		vma = vma->vm_next;
	}
    printk("> DMA decrypted for %s: %i pages (%i MB), decrypt vma\n", task->comm, pgs_decrypted, pgs_decrypted*4/1024);
}

void decrypt_vma(struct mm_struct *mm, struct vm_area_struct *vma, int * pgs_decrypted)
{
	struct page* pg;
	pte_t *ptep, pte;
	long unsigned int pg_count = 0;
	unsigned long linear_add;
	unsigned i;
	//calculate the number of pages in the vma
	pg_count = (vma->vm_end-vma->vm_start)/PAGE_SIZE;
#ifdef DEBUG
	total_pg_count += pg_count;
	printk("total pg count is %lu \n", total_pg_count);
#endif
	
	linear_add = vma->vm_start;
	for (i = 0; i < pg_count; i++, linear_add += PAGE_SIZE) {
		pg = vir_to_page(mm, linear_add);
		ptep = vir_to_pte(mm, linear_add);
		if (pg == NULL || ptep == NULL) {
			continue;
		}

		if (!PageEncrypted(pg))
			continue;

		if (decrypt_page(pg)) {
            if (pgs_decrypted != NULL) {
                *pgs_decrypted += 1;
            }
			pte = pte_mkdecrypted(*ptep);
			set_pte_at(mm, linear_add, ptep, pte);
			flush_tlb_page(vma, linear_add);
		}
	}
}

void updateVmallocPte(void)
{
	struct vm_struct *vma;
	unsigned long count = 0;
	struct page *page;
	pte_t *ptep, pte;
	void *addr;
	unsigned long pfn;

	read_lock(&vmlist_lock);

	for (vma = vmlist; vma; vma = vma->next) {
		if (vma->size == PAGE_SIZE) {
			continue;
		}

		for (addr = vma->addr; addr < vma->addr + vma->size - PAGE_SIZE; addr += PAGE_SIZE) {
			if ((unsigned long) addr < VMALLOC_START) {
			//	printk("addr < START !!!\n");
			//	printk("vma->addr is: %p, count=%lu\n", addr, count);
				continue;
			}
			if ((unsigned long) addr >= VMALLOC_END) {
			//	printk("addr >= END !!!\n");
			//	printk("vma->addr is: %p, count=%lu\n", addr, count);
				break;
			}

			ptep = virt_to_pte_k((unsigned long) addr);
			if (ptep == NULL){
				continue;
			}
				
			if (!pte_present(*ptep)) {
				continue;
			}

			pfn = pte_pfn(*ptep);

			if (!pfn_valid(pfn)) {
				continue;
			}

			page = pte_page(*ptep);
			if (page == NULL) {
				continue;
			}

			if (PageEncrypted(page)) {
				printk("vmalloc PageEncrypted @pfn %lu, addr %lx\n", page_to_pfn(page), (unsigned long) addr);
				pte = *ptep;
				pte = pte_mkencrypted(pte);
				pte = pte_mkold(pte);
				set_pte_at(&init_mm, (unsigned long) addr, ptep, pte);
				flush_tlb_kernel_page((unsigned long) addr);
			}
			count++;
		}
		  
	}
	read_unlock(&vmlist_lock);
	//printk("vmalloc has %lu pages, total mem %luKB\n", count, count * PAGE_SIZE / 1024);
}

void updateTaskPte(struct task_struct *task)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int i;

	mm = task->mm;
	if (!mm) {
		return;
	}

	vma = mm->mmap;
	for (i = 0; i < mm->map_count && vma != NULL; i++) {
		updateVmaPte(mm, vma);
		vma = vma->vm_next;
	}
}

void updateVmaPte(struct mm_struct *mm, struct vm_area_struct *vma)
{
	struct page* pg;
	pte_t *ptep, pte;
	long unsigned int pg_count = 0;
	unsigned long linear_add;
	unsigned i;

	//calculate the number of pages in the vma
	pg_count = (vma->vm_end - vma->vm_start) / PAGE_SIZE;
	linear_add = vma->vm_start;
	for (i = 0; i < pg_count; i++, linear_add += PAGE_SIZE) {
		pg = vir_to_page(mm, linear_add);
		ptep = vir_to_pte(mm, linear_add);
		if (pg == NULL || ptep == NULL) {
			continue;
		}
		if (PageEncrypted(pg)) {
			ptep_test_and_clear_young(vma, linear_add, ptep);
			pte = pte_mkencrypted(*ptep);
			set_pte_at(mm, linear_add, ptep, pte);
			flush_tlb_page(vma, linear_add);
		}
	}
}
/*
 Walk through the page table in the memory descriptor mm
 and find the pages corresponds to the given virtual address vir
 we skip the pages are not present in memory
*/
struct page* vir_to_page(struct mm_struct *mm, unsigned long vir)
{
	pte_t *ptep, pte;
	struct page* pg;

	ptep = vir_to_pte(mm, vir);
	if (ptep == NULL) {
		//printk("pte pointer is null\n");
		return NULL;
	}

	pte = *ptep;
	if (pte_present(pte)) {
		//we only want to encrypt pages that are present in memory
		pg = pte_page(pte); 
		return pg;
	}
	else {
		return NULL;
	}
}

/*
* Walk the kernel page table to find the pte of a kernel virtual address.
*/
pte_t* virt_to_pte_k(const unsigned long virt)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset_k(virt);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto out;

	pud = pud_offset(pgd, virt);
	if (pud_none(*pud) || pud_bad(*pud))
		goto out;

	pmd = pmd_offset(pud, virt);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto out;

	ptep = pte_offset_map(pmd, virt);
	if (ptep == NULL)
		goto out;

	return ptep;

out:
	return NULL;
}

pte_t* vir_to_pte(struct mm_struct *mm, unsigned long vir)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, vir);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto out;

	pud = pud_offset(pgd, vir);
	if (pud_none(*pud) || pud_bad(*pud))
		goto out;

	pmd = pmd_offset(pud, vir);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto out;

	ptep = pte_offset_map(pmd, vir);
	if (!ptep)
		goto out;

	return ptep;

out:
#ifdef DEBUG
	//printk(KERN_INFO "pgt walk error\n");
#endif
	return NULL;
}

unsigned long vir_to_phy(struct mm_struct *mm, unsigned long vir)
{
	pte_t *ptep, pte;
	unsigned long phy_add = 0;

	ptep = vir_to_pte(mm, vir);
	if (ptep == NULL) {
		printk(KERN_INFO "pte pointer is null\n");
		return 0;
	}

	pte = *ptep;
	phy_add = pte_val(pte);
	printk("vm_start physical address is 0x%lx\n", phy_add);
	return phy_add;
}

/* Export some unexported symbols.
 */
void flush_tlb_kernel_page_EXP(unsigned long kaddr)
{
    flush_tlb_kernel_page(kaddr);
}
EXPORT_SYMBOL(flush_tlb_kernel_page_EXP);

char* getPathName(struct file *file)
{
	char *tmp;
	char *pathname;
	struct path path;

	path = file->f_path;
	path_get(&file->f_path);

	tmp = (char *)__get_free_page(GFP_TEMPORARY);

	if (!tmp) {
		path_put(&path);
		return NULL;
	}

	pathname = d_path(&path, tmp, PAGE_SIZE);
	path_put(&path);

	if (IS_ERR(pathname)) {
		free_page((unsigned long)tmp);
		return NULL;
	}
	else {
		free_page((unsigned long)tmp);
		return pathname;
	}
}

module_init(mem_encrypt_init);
