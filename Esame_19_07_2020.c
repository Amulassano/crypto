 #include <openssl/bn.h>

int main(){

	  BIGNUM *p=BN_new();
  	  BIGNUM *alfa=BN_new();
	  BIGNUM *due=BN_new();
	  BN_set_bit(due, 2);
  /* init the random engine: */
  int rc = RAND_load_file("/dev/random", 64);
  if(rc != 64) {
      handle_errors();
  }

  // generate a 16 bit prime (a very small one)
  // BN_generate_prime_ex is deprecated in OpenSSL 3.0 use the one below instead (also has a context for more generic generation) 
  // int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb, BN_CTX *ctx);
  if (!BN_generate_prime_ex2(prime1, 256, 0, NULL, NULL, NULL)) 
    handle_errors();

  // generate a 16 bit prime (a very small one)
  // BN_generate_prime_ex is deprecated in OpenSSL 3.0 use the one below instead (also has a context for more generic generation) 
  // int BN_generate_prime_ex2(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb, BN_CTX *ctx);
  alfa = BN_rand_range(due, p);
  send_to_sara(alfa);
  send_to_sara(p);

  BIGNUM *d=BN_new();
  BIGNUM *B=BN_new();
  d = BN_rand_range(due, p);
  BN_CTX *ctx=BN_CTX_new();
  if (!BN_mod_exp(B,alfa,d,p,ctx)) {
    ERR_print_errors_fp(stdout);
    exit(1);
  }
  send_to_sara(B);
  BIGNUM *A=BN_new();	
  A = receive_from_sara();
  BIGNUM *k=BN_new();
  if (!BN_mod_exp(k,A,d,p,ctx)) {
    ERR_print_errors_fp(stdout);
    exit(1);
  }


	return 0;
}
