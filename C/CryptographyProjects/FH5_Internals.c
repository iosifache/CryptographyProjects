#pragma region IncludedHeaders

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include "FH5_Internals.h"
#include "RSA_Internals.h"
#include "RSA_Input.h"
#include "UTL_Input.h"
#include "UTL_Output.h"
#include "UTL_Types.h"
#include "UTL_Macros.h"

#pragma endregion

#pragma region InternalFunctions

void _XORHashes(uchar *x, const uchar *y){

	int i;

	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		x[i] = x[i] ^ y[i];

}

char *_GenerateBlindnessFactor(const char *passphase, size passphase_length, int rounds){

	SHA512_CTX sha_ctx;
	uchar nounce[NOUNCE_LENGTH];
	uchar *factor = NULL, *hash = NULL, *hashed = NULL;
	int i, is_error = 1;

	// Allocate memory
	factor = (uchar *)calloc(1, SHA512_DIGEST_LENGTH * sizeof(uchar));
	RETURN_CHECK_RET_VAL_NOT_EQUAL(factor, NULL, NULL);
	hash = (uchar *)malloc(SHA512_DIGEST_LENGTH * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(hash, NULL, FAIL_GenerateBlindnessFactor_1);
	hashed = (uchar *)malloc((passphase_length + SHA512_DIGEST_LENGTH) * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(hashed, NULL, FAIL_GenerateBlindnessFactor_2);

	// Generate random nounce
	RAND_bytes(nounce, NOUNCE_LENGTH);

	// Generate generations of U
	SHA512_Init(&sha_ctx);
	for (i = 0; i < rounds; i++){

		// Generate hash
		memcpy(hashed, passphase, passphase_length);
		if (i == 0){
			memcpy(hashed + passphase_length, nounce, NOUNCE_LENGTH);
			SHA512_Update(&sha_ctx, hashed, passphase_length + NOUNCE_LENGTH);
		}
		else{
			memcpy(hashed + passphase_length, hash, SHA512_DIGEST_LENGTH);
			SHA512_Update(&sha_ctx, hashed, passphase_length + SHA512_DIGEST_LENGTH);
		}
		SHA512_Final(hash, &sha_ctx);

		// Update factor
		_XORHashes(factor, hash);

	}
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	free(hashed);
	FAIL_GenerateBlindnessFactor_2:
		free(hash);
	FAIL_GenerateBlindnessFactor_1:
		if (is_error){
			free(factor);
			factor = NULL;
		}

	// Return
	return factor;

}

uchar *_CreateBlindMessage(const uchar *message, size message_length, const RSA *key, const char *passphase, size passphase_length, int rounds, size *blind_message_length, uchar **returned_factor){

	BN_CTX *bn_ctx = NULL;
	BIGNUM *n = NULL, *e = NULL, *d = NULL, *m = NULL, *f = NULL, *b = NULL, *b_exp = NULL;
	uchar *factor = NULL, *blinded_message = NULL;
	int is_error = 1;

	// Allocate big number context and variables
	bn_ctx = BN_CTX_new();
	n = BN_new();
	e = BN_new();
	d = BN_new();
	m = BN_new();
	f = BN_new();
	b = BN_new();
	b_exp = BN_new();

	// Allocate result
	blinded_message = (uchar *)malloc(MAX_MESSAGE_LENGTH * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(blinded_message, NULL, FAIL_CreateBlindMessage_1);

	// Transform message to big number
	BN_bin2bn(message, message_length, m);

	// Create blindness factor and transform to big number
	factor = _GenerateBlindnessFactor(passphase, passphase_length, rounds);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(factor, NULL, FAIL_CreateBlindMessage_2);
	BN_bin2bn(factor, SHA512_DIGEST_LENGTH, f);

	// Get RSA parameters
	RSA_get0_key(key, &n, &e, &d);

	// Create blind message
	BN_mod_exp(b_exp, f, e, n, bn_ctx);
	BN_mod_mul(b, b_exp, m, n, bn_ctx);

	// Save results
	*returned_factor = factor;
	*blind_message_length = BN_bn2bin(b, blinded_message);
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_CreateBlindMessage_2:
		if (is_error){
			free(blinded_message);
			blinded_message = NULL;
		}
	FAIL_CreateBlindMessage_1:
		BN_CTX_free(bn_ctx);
		BN_free(m);
		BN_free(f);
		BN_free(b);
		BN_free(b_exp);

	// Return
	return blinded_message;

}

uchar *_SignBlindMessage(RSA *key, const uchar *blind_message, size blind_message_length){

	return RSA_decrypt(key, blind_message, blind_message_length);

}

uchar *_GetSignature(const RSA *key, const uchar *signed_blind_message, const uchar *factor){
	
	BN_CTX * bn_ctx = NULL;
	BIGNUM *n = NULL, *e = NULL, *d = NULL, *m = NULL, *k = NULL, *k_inv = NULL, *s = NULL;
	uchar *signature = NULL;

	// Allocate big number variables
	bn_ctx = BN_CTX_new();
	n = BN_new();
	e = BN_new();
	d = BN_new();
	m = BN_new();
	k = BN_new();
	k_inv = BN_new();
	s = BN_new();

	// Allocate signature
	signature = (uchar *)malloc(MAX_MESSAGE_LENGTH * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(signature, NULL, FAIL_GetSignature_1);

	// Convert signed blind message to big number FIXME
	BN_bin2bn(signed_blind_message, MAX_MESSAGE_LENGTH, m);

	// Get RSA parameters
	RSA_get0_key(key, &n, &e, &d);

	// Convert factor to big number and compute its inverse
	BN_bin2bn(factor, SHA512_DIGEST_LENGTH, k);
	BN_mod_inverse(k_inv, k, n, bn_ctx);

	// Get signature
	BN_mod_mul(s, m, k_inv, n, bn_ctx);

	// Dump signature
	BN_bn2bin(s, signature);

	// Free memory
	FAIL_GetSignature_1:
		BN_CTX_free(bn_ctx);
		BN_free(m);
		BN_free(k);
		BN_free(k_inv);
		BN_free(s);

	// Return
	return signature;

}

#pragma endregion

#pragma region ExportedFunctions

int CreateBlindSignature(const char *input_filename, const char *key_filename, const char *passphase, int passphase_length, int rounds, char *signature_filename){

	RSA *key = NULL;
	uchar *message = NULL, *factor = NULL, *blind_message = NULL, *signed_blind_message = NULL, *signature = NULL;
	size message_length, blind_message_length;
	int is_error = 1;

	// Read key from file
	key = RSA_read_private_key(key_filename, NULL, 0);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, 1);

	// Read message from file
	message = read_file_content(input_filename, &message_length);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(message, NULL, FAIL_CreateBlindSignature_1);

	// Read content of file and create blind message based on it, namely (message * (factor ^ e)) mod n
	blind_message = _CreateBlindMessage(message, message_length, key, passphase, passphase_length, rounds, &blind_message_length, &factor);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(blind_message, NULL, FAIL_CreateBlindSignature_2);

	// Sign file, namely factor * (message ^ d) mod n
	signed_blind_message = _SignBlindMessage(key, blind_message, blind_message_length);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(signed_blind_message, NULL, FAIL_CreateBlindSignature_3);

	// Get signature, namely ((factor ^ (-1)) *  (factor * (message ^ d))) mod n
	signature = _GetSignature(key, signed_blind_message, factor);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(signature, NULL, FAIL_CreateBlindSignature_4);

	// Dump signature to file
	dump_to_file(signature_filename, signature, MAX_MESSAGE_LENGTH);

	// Mark function as successful
	is_error = 0;

	// Free memory
	free(signature);
	FAIL_CreateBlindSignature_4:
		free(signed_blind_message);
	FAIL_CreateBlindSignature_3:
		free(factor);
		free(blind_message);
	FAIL_CreateBlindSignature_2:
		free(message);
	FAIL_CreateBlindSignature_1:
		RSA_free(key);

	// Return
	return is_error;

}

int VerifyBlindSignature(const char *input_filename, const char *key_filename, const char *signature_filename){

	RSA *key = NULL;
	uchar *content = NULL, *signature = NULL, *new_content = NULL;
	size content_size, signature_size, new_content_size;
	int is_invalid = 1;

	// Read key from file
	key = RSA_read_private_key(key_filename, NULL, 0);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, 1);

	// Read signed content from file
	content = read_file_content(input_filename, &content_size);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(content, NULL, FAIL_VerifyBlindSignature_1);

	// Read signature from file
	signature = read_file_content(signature_filename, &signature_size);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(signature, NULL, FAIL_VerifyBlindSignature_2);

	// Verify the signature, namely if signature ^ e == m mod n
	new_content = RSA_encrypt(key, signature, signature_size, &new_content_size);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(new_content, NULL, FAIL_VerifyBlindSignature_3);
	is_invalid = (memcmp(content, new_content, content_size) == 0) ? 0 : 1;
	
	// Free memory
	free(new_content);
	FAIL_VerifyBlindSignature_3:
		free(signature);
	FAIL_VerifyBlindSignature_2:
		free(content);
	FAIL_VerifyBlindSignature_1:
		RSA_free(key);

	// Return
	return is_invalid;

}

#pragma endregion