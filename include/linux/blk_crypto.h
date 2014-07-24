#ifndef BLK_CRYPTO_H
#define BLK_CRYPTO_H

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <asm/highmem.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <crypto/aes.h>
extern struct blkcipher_desc encrypt_desc;
static const char blkcipher_alg[] = "cbc(aes)";

void hexdump(unsigned char *buf, unsigned int len, unsigned int start);
bool encrypt_page(struct page* pg);
bool decrypt_page(struct page* pg);
int init_decrypt_blkcipher_desc(struct blkcipher_desc *desc, const u8 *key,
			       unsigned int key_len, const u8 *iv,
			       unsigned int ivsize);
int init_blkcipher_desc(struct blkcipher_desc *desc);
int blkcipher_setkey(struct blkcipher_desc *desc, const u8 *key, unsigned key_len, const u8* iv, unsigned int ivsize);
void print_page_stats(int reset);

#endif /* end of include guard: BLK_CRYPTO_H */

