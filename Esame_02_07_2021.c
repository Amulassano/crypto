#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#define MAX 32
#define KEY_LENGTH  2048
#define ENCRYPT 1

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(){
    unsigned char r1[MAX];
    unsigned char r2[MAX];
    unsigned char iv[16];
    unsigned char key_symm[MAX];
    EVP_PKEY *rsa_keypair = NULL;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();


    if(RAND_load_file("/dev/random", MAX) != MAX) 
        handle_errors();

    if(!RAND_bytes(r1,MAX))
        handle_errors();

    if(!RAND_bytes(iv,128))
        handle_errors();

    if(!RAND_bytes(r2,MAX))
        handle_errors();

   for(int i=0;i<MAX;i++)
	key_simm[i] = r1[i]^r2[i];

   if((rsa_keypair = EVP_RSA_gen(KEY_LENGTH)) == NULL ) 
        handle_errors();

    // Serialize RSA keypair to binary format
    unsigned char *rsa_priv_key = NULL;
    int rsa_priv_key_len = i2d_RSAPrivateKey(rsa_keypair, &rsa_priv_key);
    if (rsa_priv_key_len < 0) handle_errors();

   if(!EVP_CipherInit(ctx,EVP_aes_256_cbc(), key_symm, iv, ENCRYPT))
        handle_errors();

   unsigned char payload[KEY_LENGTH+16];
   int update_len;
   int ciphertext_len=0;

   EVP_CipherUpdate(ctx,payload,&update_len,rsa_keypair,EVP_PKEY_size(rsa_keypair));
   ciphertext_len+=update_len;

   EVP_CipherFinal_ex(ctx,payload+ciphertext_len,&final_len);

   EVP_CIPHER_CTX_free(ctx);
   EVP_PKEY_free(keypair);


   return 0;
}

   	
