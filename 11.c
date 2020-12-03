/* 11.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
// initial BIGNUM print feature
void printBN(char *msg, BIGNUM * a) {
	char *number_str = BN_bn2hex(a); 
	printf("%s %s\n", msg, number_str); 
	OPENSSL_free(number_str);}
int main () {
	BN_CTX *ctx = BN_CTX_new();
	// initial p, q, e, d, 1
	BIGNUM *p = BN_new(); BIGNUM *q = BN_new();
	BIGNUM *e = BN_new(); BIGNUM *d = BN_new();
	BIGNUM *p1 = BN_new(); BIGNUM *q1 = BN_new();
	BIGNUM *phiN = BN_new(); BIGNUM *ONE = BN_new();
	// set values
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF"); 
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3"); BN_dec2bn(&ONE, "1");
	// p1 = p-1; q1 = q-1; phi(n)=p1*q1
	BN_sub(p1,p,ONE); BN_sub(q1,q,ONE); BN_mul(phiN,p1,q1,ctx);
	// ed mod phi(n) =1 
	BN_mod_inverse(d, e, phiN, ctx); printBN("private key=", d);
	return 0;}