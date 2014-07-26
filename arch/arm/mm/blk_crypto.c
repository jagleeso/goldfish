#include <linux/blk_crypto.h>
/* #include "blk_crypto.h" */
/* #include <linux/sched.h> */
/* #include <linux/module.h> */
/* >>>>>>> experiments */

static DEFINE_SPINLOCK(lock);

static DEFINE_SPINLOCK(pg_stats_lock);

void hexdump(unsigned char *buf, unsigned int len, unsigned int start)
{
	while (len--)
		printk("%02x", *buf++ + start);
	printk("\n");
}

// Report amount decrypted every 1MB.
static int report_pages_every = 1024*1024;
static int pg_enc = 0;
static int pg_dec = 0;
void reset_pg_stats(void) 
{
	unsigned long pg_stats_flags;
    spin_lock_irqsave(&pg_stats_lock, pg_stats_flags);
    pg_enc = 0;
    pg_dec = 0;
    spin_unlock_irqrestore(&pg_stats_lock, pg_stats_flags);
}
EXPORT_SYMBOL_GPL(reset_pg_stats);

void get_pg_stats(int * enc, int * dec)
{
	unsigned long pg_stats_flags;
    spin_lock_irqsave(&pg_stats_lock, pg_stats_flags);
        *enc = pg_enc;
        *dec = pg_dec;
    spin_unlock_irqrestore(&pg_stats_lock, pg_stats_flags);
}
EXPORT_SYMBOL_GPL(get_pg_stats);

void print_page_stats(int reset)
{
    int pg_enc, pg_dec;
    get_pg_stats(&pg_enc, &pg_dec);
    printk("Page stats: pg_enc = %i, pg_dec = %i\n", pg_enc, pg_dec);
    printk("Page stats: Encrypted = %iMB, Decrypted = %iMB\n", (pg_enc*4*1024) / (1024*1024), (pg_dec*4*1024) / (1024*1024));
    /* Reset pg_stats counters so we don't accidentally recount them.
     */
    if (reset) {
        reset_pg_stats();
    }
}
EXPORT_SYMBOL_GPL(print_page_stats);

bool encrypt_page(struct page* pg_in)
{
	int ret;
	struct scatterlist sg_in;
	int offset;
	const u8 key[16]= "my key";
	const u8 iv[16]= "my iv";
	unsigned long pg_stats_flags;
	
	if (PageEncrypted(pg_in) ) {
		/* printk("%s try to encrypt an encrypted page!!! bail out\n", __func__); */
		return false;
	}

	offset = 0;
	sg_set_page(&sg_in, pg_in, PAGE_SIZE, offset);
	ret = blkcipher_setkey(&encrypt_desc, key, 16, iv, 16);
	if (ret < 0) {
		printk("init_blkciper_desc failed\n");
        BUG();
		return false;
	}

	ret = crypto_blkcipher_encrypt(&encrypt_desc, &sg_in, &sg_in, PAGE_SIZE);
	if (ret < 0) {
		pr_err("crypto_blkcipher_encrypt failed(%d)\n", ret);
        BUG();
		return false;
	}

    spin_lock_irqsave(&pg_stats_lock, pg_stats_flags);
        pg_enc += 1;
    spin_unlock_irqrestore(&pg_stats_lock, pg_stats_flags);

	SetPageEncrypted(pg_in);
	/* printk("%s: page encrypted @pfn:%lu\n", __func__, page_to_pfn(pg_in)); */

	return true;
}
EXPORT_SYMBOL_GPL(encrypt_page);

bool decrypt_page(struct page* pg_in)
{
	int ret;
	struct blkcipher_desc desc;
	struct scatterlist sg_in;
	int offset = 0;

	const u8 key[16]= "my key";
	const u8 iv[16]= "my iv";
	unsigned long flags;

	sg_set_page(&sg_in, pg_in, PAGE_SIZE, offset);

	ret = init_decrypt_blkcipher_desc(&desc, key, 16, iv, 16);
	if (ret < 0) {
		printk("init_blkciper_desc failed\n");
		goto error;
	}

	spin_lock_irqsave(&lock, flags);
	if (!PageEncrypted(pg_in)) {
		printk("decrypt an unencrypted page !!! bail out\n");
		spin_unlock_irqrestore(&lock, flags);
		goto error;
	}

	ret = crypto_blkcipher_decrypt(&desc, &sg_in, &sg_in, PAGE_SIZE);
	if (ret < 0) {
		printk("crypto_blkcipher_decrypt failed\n");
		spin_unlock_irqrestore(&lock, flags);
		goto error;
	}
	/* printk("%s:page decrypted @pfn by %s: %lu\n", __func__, current->comm, page_to_pfn(pg_in)); */
	ClearPageEncrypted(pg_in);

    /* Modify pg_stats (don't need to grab pg_stats_lock since we have lock).
     */
    pg_dec += 1;
    if (pg_dec % report_pages_every == 0) {
        printk("%iMB decrypted\n", (pg_dec*4*1024) / (1024*1024));
    }

	spin_unlock_irqrestore(&lock, flags);
	crypto_free_blkcipher(desc.tfm);
	return true;
	//printk(KERN_INFO "DECRYPTED: "); hexdump(memp, SIZE, 0);
error:
	crypto_free_blkcipher(desc.tfm);
	return false;

}
EXPORT_SYMBOL_GPL(decrypt_page);

int init_decrypt_blkcipher_desc(struct blkcipher_desc *desc, const u8 *key,
			       unsigned int key_len, const u8 *iv,
			       unsigned int ivsize)
{
	int ret;

	desc->tfm = crypto_alloc_blkcipher(blkcipher_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(desc->tfm)) {
		pr_err("encrypted_key: failed to load %s transform (%ld)\n",
		       blkcipher_alg, PTR_ERR(desc->tfm));
		return PTR_ERR(desc->tfm);
	}
	desc->flags = 0;

	ret = crypto_blkcipher_setkey(desc->tfm, key, key_len);
	if (ret < 0) {
		pr_err("encrypted_key: failed to setkey (%d)\n", ret);
		crypto_free_blkcipher(desc->tfm);
		return ret;
	}
	crypto_blkcipher_set_iv(desc->tfm, iv, ivsize);
	return 0;
}

int init_blkcipher_desc(struct blkcipher_desc *desc)
{
	desc->tfm = crypto_alloc_blkcipher(blkcipher_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(desc->tfm)) {
		pr_err("encrypted_key: failed to load %s transform (%ld)\n",
		       blkcipher_alg, PTR_ERR(desc->tfm));
		return PTR_ERR(desc->tfm);
	}
	desc->flags = 0;
	return 0;
}

int blkcipher_setkey(struct blkcipher_desc *desc, const u8 *key, unsigned key_len, const u8* iv, unsigned int ivsize)
{
	int ret;
	ret = crypto_blkcipher_setkey(desc->tfm, key, key_len);
	if (ret < 0) {
		pr_err("encrypted_key: failed to setkey (%d)\n", ret);
		crypto_free_blkcipher(desc->tfm);
		return ret;
	}
	crypto_blkcipher_set_iv(desc->tfm, iv, ivsize);
	return 0;
}

