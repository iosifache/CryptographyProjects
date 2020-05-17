#pragma region IncludedHeaders

#include <openssl/pem.h>

#pragma endregion

#pragma region WriteToFile

void RSA_write_key(RSA *key, const char *public_key_filename, const char *private_key_filename){

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
		PEM_write_bio_RSAPublicKey(private_key, key);
		BIO_free(private_key);
	}

}

#pragma endregion