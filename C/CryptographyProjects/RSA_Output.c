#pragma region IncludedHeaders

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include "RSA_Output.h"
#include "UTL_Logger.h"

#pragma endregion

#pragma region DumpToScreen

void RSA_dump_private_key(const RSA *key){

	BIGNUM *e = NULL, *d = NULL, *n = NULL;

	// Get parameters
	RSA_get0_key(key, &n, &e, &d);

	// Print
	COLORED_LOG(COLOR_BLUE, "Parameters of public key (n, e, d) are: (%s, %s, %s)", BN_bn2hex(n), BN_bn2hex(e), BN_bn2hex(d));

}

#pragma endregion

#pragma region WriteToFile

void RSA_write_encrypted_keys(RSA *key, const char *passcode, int passcode_length, const char *public_key_filename, const char *private_key_filename){

	BIO *public_key, *private_key;

	// Open files
	public_key = BIO_new_file(public_key_filename, "wb");
	private_key = BIO_new_file(private_key_filename, "wb");

	// Write the public key
	if (public_key != NULL){
		PEM_write_bio_RSAPublicKey(public_key, key);
		BIO_free(public_key);
	}

	// Write the private key
	if (private_key != NULL){
		if (passcode != NULL && passcode_length != 0)
			PEM_write_bio_RSAPrivateKey(private_key, key, EVP_aes_256_cbc(), passcode, passcode_length, NULL, NULL);
		else
			PEM_write_bio_RSAPrivateKey(private_key, key, NULL, NULL, 0, NULL, NULL);
		BIO_free(private_key);
	}

}

void RSA_write_keys(RSA *key, const char *public_key_filename, const char *private_key_filename){

	RSA_write_encrypted_keys(key, NULL, 0, public_key_filename, private_key_filename);

}

#pragma endregion