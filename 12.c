/* 12.c */
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
	// initial M(hex), e, n, d, Enc & Dec
	BIGNUM *M = BN_new(); BIGNUM *e = BN_new();
	BIGNUM *n = BN_new(); BIGNUM *d = BN_new();
	BIGNUM *Enc = BN_new(); BIGNUM *Dec = BN_new();
	// set values of M(hex), e, n, d
	BN_hex2bn(&M, "4120746f702073656372657421");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	// encrypt, Enc=M^e mod n
	BN_mod_exp(Enc, M, e, n, ctx); printBN("encrypted=", Enc);
	// decrypt, Dec= Enc^d mod n
	BN_mod_exp(Dec, Enc, d, n, ctx); printBN("decrypted=", Dec);
	// check decription == M
	if (BN_cmp(Dec,M)==0) {
		printf("Encrypt succeeded\n");} 
	else {
		printf("Encrypt failed\n");}
	return 0;}