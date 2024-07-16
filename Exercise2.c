/* INCLUDE OPENSSL LIBRARIES HERE */

#include <stdio.h>

#include <string.h>

#include <openssl/pem.h>

#include <openssl/evp.h>

#include <openssl/rsa.h>

#define MAX_BUFFER 1024

//with the private key i decrypt the key and use it to decrypt the file

EVP_PKEY *my_private_key;

//my_private_key is initialized (e.g., by reading it from a file)

FILE *f_msg, *key; // both files are open in read mode

char iv[16];

/***********************

 the snapshot of the code starts here: decrypt the enveloped-data

*************************/

EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

int ciphertext_len;
int len;
int plain_text=0;
unsigned char enc_key[16]; //128 bit is the key of AES
n_read = fread(enc_key,1,16,key);
EVP_SealInit(ctx, EVP_aes_256_cbc(), enc_key,
		encrypted_key_len, iv, pub_key, 1);
unsigned char ciphertext[MAX_BUFFER+16];
unsigned char buffer[MAX_BUFFER];
FILE *f_out;
f_out = fopen("f_msg_decrypted.txt","wb");
while((n_read = fread(buffer,1,MAX_BUFFER,f_msg)) > 0){
    printf("n_Read=%d-",n_read);
    
     EVP_OpenUpdate(ctx, buffer, &len, ciphertext, ciphertext_len);
      plaintext_len += len;
    printf("length=%d\n",len);
    if(fwrite(buffer, 1, len,f_out) < len){
         fprintf(stderr,"Error writing the output file\n");
         abort();
     }
}
EVP_OpenFinal(ctx, buffer + len, &len);
plaintext_len += len;
if(fwrite(buffer,1, len, f_out) < len){
     fprintf(stderr,"Error writing in the output file\n");
     abort();
 }
EVP_CIPHER_CTX_free(ctx);
fclose(key);

fclose(f_out);

fclose(f_msg);

// close everything properly
