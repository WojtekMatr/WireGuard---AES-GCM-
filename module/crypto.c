// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#include "messages.h"
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <crypto/aead.h>

#define KEY_LENGHT 32
#define IV_SIZE 12
int wg_aes_gcm_encrypt_sg(struct scatterlist *sg, size_t plain_len,
			  const u8 *iv, const u8 *key)
{
        pr_info("Poczatek SZYFROWANIA \n\n");
      	pr_info("Dlugosc tekstu jawnego =%zu, Dane = %p, IV = %p, Klucz=%p\n"
      	        ,plain_len, sg, iv, key);
      	pr_info("SG: %*ph\n", plain_len, sg);
      	pr_info("IV: %*ph\n", IV_SIZE, iv);
      	pr_info("Klucz: %*ph\n", KEY_LENGHT, key);
  	struct crypto_aead *transformation;

	
	struct aead_request *request;
	//zmienna wait w crypto_wait dziala jak sygnal, ze w naszym szyfrowaniu asynchronicznym skonczylo sie szyfrowanie i mozemy isc dalej
	
	struct crypto_wait wait;
	int is_working;

	// 1. Alokuje obiekt transformacji kryptograficznej gcm(aes) <crypto/aead.h
	// 2. 1 atrybut to definicja ktory z szyfrow AEAD nas inetersuje
	// w bibioliotece AEAD mamy: Standardowe : gcm(aes), ccm(aes), chacha20poly1305, rfc7539(cha
	// flagi na 2 i 3 miejscu to: typ algorytmu, mask
	transformation = crypto_alloc_aead("gcm(aes)", 0, 0);
	// 2. Ustawiamy dlugosc tekstu autentyf gcm(aes), ccm(aes), chacha20poly1305, rfc7539(cha
	// flagi na 2 i 3 miejscu to: typ aikujacego na 16 bajtow
	crypto_aead_setauthsize(transformation, 16);
	crypto_aead_setkey(transformation, key, KEY_LENGHT);
	// Tworzymy obiekt ktory wrzycimy do rzadania szyfrowania,
	//1. zmienna to zmienna crpto_alloc_aead
	//2. zmienna to flaga alokacji pamieci, najprostrza flaga, oznacza ze alakowana pamiec moze spac i  odzyskiwac pamiec
	request = aead_request_alloc(transformation, GFP_KERNEL);
	request->assoclen =0;
	// Brak danych uwierzytelnianych. Uwierzytelnienie w innym folderze, zapytac sie prowadzacego. 

	/*
	crypto init wait - informuje crytop ze moja struktura wait to te wait ktore mnie interesuje i w nim chce sie spotkac
	Inicjalizujemy czekanie jako miejsce spotkania po zakonczonej operacji. Callback gdy szyfrowanie sie zakonczy*/
	crypto_init_wait(&wait);
	// flagi:
        // CRYPTO_TFM_REQ_MAY_BACKLOG - jesli sprzet jest zajety czyms innym to czeka kernel crypto na to by zaszyfrowac moje dane
        // CRYPTO_TFM_REQ_MAY_SLEEP - operacja moja moze spac
        // crypto_req_done - Zostanie wywowalany callback kiedy operacja sie skonczy wysle completion w strukturze wait
	aead_request_set_callback(request,
				  CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);

	/* 7. set_crypt – in-place, plain_len bez tagu */
	// szyfrujemy w tym samymy miejscu co jest tekst szyfrowania 2 i 3 miejsce na in i out, 4 dlugosc plain tekstu (bez tagu GCM), nonce
	aead_request_set_crypt(request, sg, sg, plain_len, (u8 *)iv);
	// SZYFRUJEMY, crypto_wait_req - wywoluje crypto_aead_encrypt jesli wynik jest  -EINPROGRESS (zwrot z crypto_aead_encrypt
	// czeka na wait ktory informuje ze crypto_req_done
    	is_working = crypto_wait_req(crypto_aead_encrypt(request), &wait); // jesli 0 - pracuje (brak bledu szyfrogramu).
    	//zwalniamy pamiec zwizana ze Aead requestem
    	u8 *tag = (u8 *)sg_virt(sg) + plain_len;
        pr_info("Tag: %*ph\n", 16, tag);
        print_hex_dump(KERN_INFO, "SZYFR i Tag Mac: ", DUMP_PREFIX_OFFSET,
               16, 1, sg_virt(sg), plain_len + 16, true);
	aead_request_free(request);
        // zwalnia pamiec zwiazana z crypto_alloc_aead
	crypto_free_aead(transformation);
	pr_info("Dane zaszyfrowane");
	return is_working;
}

int wg_aes_gcm_decrypt_sg(struct scatterlist *sg, size_t cipher_len,
			  const u8 *iv, const u8 *key)
{
        pr_info("Zaczynam deszyfrowac");

	struct crypto_aead *transformation;
	struct aead_request *request;
	struct crypto_wait wait;
	int is_working;
	pr_info("Dlugosc tekstu jawnego =%zu, Dane = %p, IV = %p, Klucz=%p\n"
      	        ,cipher_len, sg, iv, key);

	transformation = crypto_alloc_aead("gcm(aes)", 0, 0);
	
	crypto_aead_setauthsize(transformation, 16);

	crypto_aead_setkey(transformation, key, KEY_LENGHT);


	request = aead_request_alloc(transformation, GFP_KERNEL);
	request->assoclen =0;

	crypto_init_wait(&wait);
	aead_request_set_callback(request,
				  CRYPTO_TFM_REQ_MAY_SLEEP,
				  crypto_req_done, &wait);
	aead_request_set_crypt(request, sg, sg, cipher_len, (u8 *)iv);

	is_working = crypto_wait_req(crypto_aead_decrypt(request), &wait);

	aead_request_free(request);
        pr_info("Dane odszyfrowane");
	crypto_free_aead(transformation);
	return is_working;
}


