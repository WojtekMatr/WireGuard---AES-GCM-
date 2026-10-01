#ifndef _WG_CRYPTO_H
#define _WG_CRYPTO_H

#include <linux/scatterlist.h>
#include <linux/types.h>

int wg_aes_gcm_encrypt_sg(struct scatterlist *sg, size_t plain_len,
			  const u8 *iv, const u8 *key);

int wg_aes_gcm_decrypt_sg(struct scatterlist *sg, size_t cipher_len,
			  const u8 *iv, const u8 *key);

#endif /* _WG_CRYPTO_H */
