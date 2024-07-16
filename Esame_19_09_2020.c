#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#define KEY_LENGTH  2048
#define MAX 128
#define ENCRYPT 1
#define MAX_ENC_LEN 1024*1024
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(void) {
	unsigned char key[MAX];
	unsigned char key[MAX];

        ERR_load_crypto_strings(); // deprecated since version 1.1.0
        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms(); // deprecated since version 1.1.0

	if(RAND_load_file("/dev/random", 64) != 64)
            fprintf(stderr,"Error with rand init\n");

        if(!RAND_bytes(key,MAX))
            fprintf(stderr,"Error with rand generation\n");
	if(!RAND_bytes(iv,MAX))
            fprintf(stderr,"Error with rand generation\n");

        int encrypted_key_len;
        unsigned char encrypted_key[RSA_size(keypair)];


        if((encrypted_key_len = RSA_public_encrypt(strlen(key)+1, key, encrypted_key, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            handle_errors();

	send_bob(encrypted_key);

        FILE *file_in; #already with the file


	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT))
            handle_errors();

	
	unsigned char ciphertext[MAX_ENC_LEN];

        int update_len, final_len;
        int ciphertext_len=0;
        int n_read;
        unsigned char buffer[MAX_BUFFER];


        while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
            if(ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(ctx)){ //use EVP_CIPHER_get_block_size with OpenSSL 3.0+ instead
                fprintf(stderr,"The file to cipher is larger than I can manage\n");
                abort();
        }
    
        if(!EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,buffer,n_read))
            handle_errors();
        ciphertext_len+=update_len;
       }

       if(!EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len))
          handle_errors();

       ciphertext_len+=final_len;

       send_bob(ciphertext);

       EVP_CIPHER_CTX_free(ctx);

       CRYPTO_cleanup_all_ex_data(); // deprecated since version 1.1.0
       /* Remove error strings */
       ERR_free_strings(); // deprecated since version 1.1.0


       return 0;
}
	
