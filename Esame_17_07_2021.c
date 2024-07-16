#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char *result){

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
            return 1; 
    strcat(message,key);

    EVP_DigestUpdate(md, message, (keylenght+message));

    unsigned char digest_pre[message_len+keylenght];
    int md_len;

    EVP_DigestFinal(md, digest, &md_len);	
    EVP_MD_CTX_free(md);

    EVP_MD_CTX *md = EVP_MD_CTX_new();

    if(!EVP_DigestInit(md, EVP_sha256()))
            return 1; 

    unsigned char digest[message_len+keylenght];

    EVP_DigestUpdate(md, digest_pre, md_len);
    int md_len;

    EVP_DigestFinal(md, digest, &md_len);	
    EVP_MD_CTX_free(md);


    int encrypted_data_len;

    if((encrypted_data_len = RSA_public_encrypt((md_len+1), digest, result, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            return 1; 
    
    return 0;
}
