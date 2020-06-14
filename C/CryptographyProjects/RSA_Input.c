#pragma region IncludedHeaders

#include <openssl/pem.h>
#include <string.h>
#include "RSA_Input.h"

#pragma endregion

#pragma region GlobalVariables

char *global_passcode;
int global_passcode_length;

#pragma endregion

#pragma region Callbacks

int _pem_password_callback(char *buffer, int max_length, int flag, void *ctx){

	// Check length
	if (global_passcode_length > max_length)
		return 0;

	// Copy
	memcpy(buffer, global_passcode, global_passcode_length);

	// Return
	return global_passcode_length;

}

#pragma endregion

#pragma region ReadFromFile

RSA *_RSA_read_key(const char *key_filename, int is_private, const char *passcode, int passcode_length){

	BIO *key_file = NULL;
	RSA *key = NULL;

	// Allocate new RSA key
	key = RSA_new();
	if (key == NULL)
		return NULL;

	// Read file and key
	key_file = BIO_new_file(key_filename, "r");
	if (key_file == NULL)
		return NULL;
	if (is_private)
		if (passcode != NULL){

			// Copy password into global variable
			global_passcode = (char *)malloc(passcode_length * sizeof(char));
			if (global_passcode == NULL)
				goto FAIL_RSA_read_key;
			global_passcode_length = passcode_length;
			memcpy(global_passcode, passcode, passcode_length);

			// Read password
			PEM_read_bio_RSAPrivateKey(key_file, &key, _pem_password_callback, NULL);

		}
		else
			PEM_read_bio_RSAPrivateKey(key_file, &key, NULL, NULL);
	else
		PEM_read_bio_RSAPublicKey(key_file, &key, NULL, NULL);

	// Close file
	FAIL_RSA_read_key:
		BIO_free(key_file);

	// Return
	return key;

}

RSA *RSA_read_public_key(const char *public_key_filename){

	return _RSA_read_key(public_key_filename, 0, NULL, 0);

}

RSA *RSA_read_private_key(const char *private_key_filename, const char *passcode, int passcode_length){

	return _RSA_read_key(private_key_filename, 1, passcode, passcode_length);

}

#pragma endregion