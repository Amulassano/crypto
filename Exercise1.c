/* INCLUDE OPENSSL LIBRARIES HERE */

#include <stdio.h>

#include <openssl/rand.h>

#include <string.h>

#include <openssl/evp.h>

#include <openssl/rsa.h>



#define ENCRYPT 1

#define MAX 128

/***********************

 the snapshot of the code starts here

*************************/



// generate two strong random 128-bit integers, name it rand1 and rand2

unsigned char rand1[MAX];

unsigned char rand2[MAX];

 if(RAND_load_file("/dev/random", 64) != 64)

        fprintf(stderr,"Error with rand init\n");


if(!RAND_bytes(rand1,MAX))


        fprintf(stderr,"Error with rand generation\n");

if(!RAND_bytes(rand2,MAX))


        fprintf(stderr,"Error with rand generation\n");

// compute the first key 

int k1 = (rand1+ rand2) * (rand1 - rand2) % (2**128);

// compute the second key 

int k2 = (rand1+ rand2) / (rand1 - rand2) % (2**128);

// Encrypt k2 using k1 using a strong encryption algorithm (and mode) of your choice, call it enc_k2.

unsigned char iv[]  = "1111111111111111";



EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

EVP_CipherInit(ctx,EVP_aes_128_cbc(), k1, iv, ENCRYPT);

int update_len, final_len;

int enc_k2t_len=0;

unsigned char enc_k2[16+16];

EVP_CipherUpdate(ctx,enc_k2,&update_len,plaintext,strlen(plaintext));

enc_k2_len+=update_len;

EVP_CipherFinal_ex(ctx,enc_k2+enc_k2_len,&final_len);

enc_k2_len+=final_len;



// Generate an RSA keypair of at least 2048 bit modulus

RSA *rsa_keypair = NULL;

BIGNUM *bne = NULL;



int bits = 2048;

unsigned long e = RSA_F4;

bne = BN_new();

rsa_keypair = RSA_new();

RSA_generate_key_ex(rsa_keypair, bits, bne, NULL);

// Encrypt enc_k2 using the just generated RSA key.

int encrypted_data_len;

unsigned char encrypted_data[RSA_size(keypair)];

encrypted_data_len = RSA_public_encrypt(strlen(msg)+1, msg, enc_k2, keypair, RSA_PKCS1_OAEP_PADDING);



EVP_CIPHER_CTX_free(ctx);

RSA_free(keypair);

// close everything properly
