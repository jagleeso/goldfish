#ifndef TCM_HEAP_H
#define TCM_HEAP_H

void *tcm_code_alloc(size_t len);
void tcm_code_free(void *addr);
void tcm_code_kzfree(void *addr);
void *tcm_code_alloc_aligned(size_t len, unsigned long alignment_order);
void * get_tcm_code_offset(void);
unsigned long get_tcm_code_size(void);
int tcm_code_initialized(void);

#endif /* end of include guard: TCM_HEAP_H */
