#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char *result){

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
            return 1; 
   // strcat(message,key);

    EVP_DigestUpdate(md, message, message_len);
    EVP_DigestUpdate(md, key, keylenght);

    unsigned char digest_pre[EVP_MD_size(EVP_sha256())];
    int md_len;

    EVP_DigestFinal(md, digest, &md_len);	
    EVP_MD_CTX_free(md);

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
            return 1; 

    unsigned char digest[EVP_MD_size(EVP_sha256())];

    EVP_DigestUpdate(md, digest_pre, md_len);
    int md_len;

    EVP_DigestFinal(md, digest, &md_len);	
    EVP_MD_CTX_free(md);

    //RSA encr
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
      
    int encrypted_data_len;

    if (EVP_PKEY_encrypt(enc_ctx, result, &encrypted_msg_len, digest, strlen(digest)) <= 0) {
        handle_errors();
    }
    
    return 0;
}
