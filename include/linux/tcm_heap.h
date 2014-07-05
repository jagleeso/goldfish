#ifndef TCM_HEAP_H
#define TCM_HEAP_H

void *tcm_code_alloc(size_t len);
void tcm_code_free(void *addr, size_t len);
void *tcm_code_alloc_aligned(size_t len, unsigned long alignment_order);

#endif /* end of include guard: TCM_HEAP_H */

