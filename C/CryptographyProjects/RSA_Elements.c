#pragma region IncludedHeaders

#include "RSA_Elements.h"

#pragma endregion

#pragma region GenerateKeyPairFunctions

RSA *RSA_generate_manual_key(int public_exponent){

	RSA *result;
	BN_CTX *ctx;
	BIGNUM* p, *q, *n, *e, *d, *dp, *dq, *q_inv, *phi, *dec_p, *dec_q, *one, *gcd;
	int prime_check;

	// Allocate result key
	result = RSA_new();
	if (result == NULL)
		return NULL;

	// Allocate big numbers variables
	p = BN_new();
	q = BN_new();
	n = BN_new();
	e = BN_new();
	d = BN_new();
	dp = BN_new();
	dq = BN_new();
	q_inv = BN_new();
	phi = BN_new();
	dec_p = BN_new();
	dec_q = BN_new();
	one = BN_new();
	gcd = BN_new();

	// Create context
	ctx = BN_CTX_new();

	// Get a public exponent, e
	BN_set_word(e, public_exponent);

	// Init one
	BN_one(one);

	// Generate strong parameters
	do {

		// Generate primes p and q
		BN_generate_prime_ex(p, PRIMES_BITLENGTH, 0, NULL, NULL, NULL);
		BN_generate_prime_ex(q, PRIMES_BITLENGTH, 0, NULL, NULL, NULL);

		// Generate modulo N
		BN_mul(n, p, q, ctx);

		// Generate Euler's totient, phi
		BN_sub(dec_p, p, one);
		BN_sub(dec_q, q, one);
		BN_mul(phi, dec_p, dec_q, ctx);

		// Check if phi and e are primes
		BN_gcd(gcd, phi, e, ctx);
		prime_check = BN_cmp(gcd, one);

	} while (!BN_is_one(gcd));

	// Compute d
	BN_mod_inverse(d, e, phi, ctx);

	// Compute dP, dQ and qInv
	BN_mod(dp, d, dec_p, ctx);
	BN_mod(dq, d, dec_q, ctx);
	BN_mod_inverse(q_inv, q, p, ctx);

	// Save key
	RSA_set0_key(result, n, e, d);
	RSA_set0_factors(result, p, q);
	RSA_set0_crt_params(result, dp, dq, q_inv);

	// Return
	return result;

}

RSA *RSA_generate_auto_key(int public_exponent){

	RSA *result;
	BIGNUM *e;
	int is_generated;

	// Allocate result key
	result = RSA_new();
	if (result == NULL)
		return NULL;

	// Allocate big number value and init public exponent
	e = BN_new();
	BN_set_word(e, public_exponent);

	// Generate key
	do {
		is_generated = RSA_generate_key_ex(result, KEY_SIZE, e, NULL);
	} while (!is_generated);

	// Free big number value
	BN_free(e);

	// Return
	return result;

}

#pragma endregion

#pragma region Encryption

uchar *RSA_encrypt(RSA *key, const uchar *plaintext, size length, int *ciphertext_length){

	BN_CTX *ctx;
	BIGNUM *e, *d, *n, *p, *c;
	char *encrypted;

	// Allocate result
	encrypted = (uchar *)malloc(BLOCK_SIZE * sizeof(uchar));
	if (encrypted == NULL)
		return NULL;

	// Allocate big number variables
	e = BN_new();
	d = BN_new();
	n = BN_new();
	p = BN_new();
	c = BN_new();

	// Get RSA parameters
	RSA_get0_key(key, &n, &e, &d);

	// Create context
	ctx = BN_CTX_new();

	// Init big number
	BN_bin2bn(plaintext, length, p);

	// Encrypt
	BN_mod_exp(c, p, e, n, ctx);

	// Save result
	*ciphertext_length = BN_bn2bin(c, encrypted);

	// Free big number variables
	BN_free(p);
	BN_free(c);

	// Return
	return encrypted;

}

#pragma endregion

#pragma region Decryption

uchar *RSA_decrypt(RSA *key, const uchar *ciphertext, size length){

	BN_CTX *ctx;
	BIGNUM *n = NULL, *e = NULL, *d = NULL, *c = NULL, *p = NULL;
	char *decrypted;

	// Allocate result
	decrypted = (uchar*)malloc(BLOCK_SIZE * sizeof(uchar));
	if (decrypted == NULL)
		return NULL;

	// Allocate big number variables
	e = BN_new();
	d = BN_new();
	n = BN_new();
	p = BN_new();
	c = BN_new();

	// Get RSA parameters
	RSA_get0_key(key, &n, &e, &d);

	// Create context
	ctx = BN_CTX_new();

	// Init big number
	c = BN_new();
	BN_bin2bn(ciphertext, length, c);

	// Encrypt
	BN_mod_exp(p, c, d, n, ctx);

	// Save result
	BN_bn2bin(p, decrypted);

	// Free big number variables
	BN_free(p);
	BN_free(c);
	BN_free(n);
	BN_free(e);
	BN_free(d);

	// Return
	return decrypted;

}

#pragma endregion