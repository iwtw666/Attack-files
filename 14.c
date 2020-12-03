/* 14.c */
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
	// initial M1(hex),M2(hex), n, d, Sig1, Sig2
	BIGNUM *M1 = BN_new(); BIGNUM *M2 = BN_new();
	BIGNUM *n = BN_new(); BIGNUM *d = BN_new();
	BIGNUM *Sig1 = BN_new(); BIGNUM *Sig2 = BN_new();
	// set values of Ms(hex), n, d, Sigs
	BN_hex2bn(&M1, "49206f776520796f752024323030302e");
	BN_hex2bn(&M2, "49206f776520796f752024333030302e");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	// sign, Sig=M^d mod n
	BN_mod_exp(Sig1, M1, d, n, ctx); printBN("Signature1=", Sig1);
	BN_mod_exp(Sig2, M2, d, n, ctx); printBN("Signature2=", Sig2);
	return 0;}