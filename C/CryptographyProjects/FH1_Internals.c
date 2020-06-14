#pragma region IncludedHeaders

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include "FH1_Internals.h"
#include "RSA_Internals.h"
#include "RSA_Output.h"
#include "UTL_Input.h"
#include "UTL_Crypto.h"
#include "UTL_Output.h"
#include "UTL_Types.h"
#include "UTL_Macros.h"

#pragma endregion

#pragma region InternalFunctions

int _ProcessFileWithRSA(const char *input_filename, const char *output_filename, RSA *key, int is_encryption){

	EVP_PKEY_CTX *pkey_ctx = NULL;
	EVP_PKEY *evp_key = NULL;
	uchar *input = NULL, *processed = NULL;
	lsize processed_input_length = 0, current_processed_length = 0, current_input_length;
	size input_length, processed_length = 0, rsa_padded_block_size;
	int ret_val, is_error = 1;

	// Get the RSA block size when OAEP padding is used
	rsa_padded_block_size = RSA_size(key) - RSA_OAEP_PADDING_LENGTH;

	// Init EVP key
	evp_key = EVP_PKEY_new();
	RETURN_CHECK_RET_VAL_NOT_EQUAL(evp_key, NULL, -1);
	ret_val = EVP_PKEY_set1_RSA(evp_key, key);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(ret_val, 0, FAIL_ProcessFileWithRSA_1);
	
	// Init context
	pkey_ctx = EVP_PKEY_CTX_new(evp_key, NULL);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(pkey_ctx, NULL, FAIL_ProcessFileWithRSA_1);
	if (is_encryption)
		ret_val = EVP_PKEY_encrypt_init(pkey_ctx);
	else
		ret_val = EVP_PKEY_decrypt_init(pkey_ctx);
	GOTO_CHECK_RET_VAL_CONDITION(ret_val <= 0, FAIL_ProcessFileWithRSA_2);
	ret_val = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING);
	GOTO_CHECK_RET_VAL_CONDITION(ret_val <= 0, FAIL_ProcessFileWithRSA_2);
	
	// Read input file
	input = read_file_content(input_filename, &input_length);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(input, NULL, FAIL_ProcessFileWithRSA_2);

	// Encrypt
	do{

		// Compute current input length and get current processed size
		if (is_encryption){
			current_input_length = (input_length - processed_input_length < rsa_padded_block_size) ? (input_length - processed_input_length) : rsa_padded_block_size;
			ret_val = EVP_PKEY_encrypt(pkey_ctx, NULL, &current_processed_length, input + processed_input_length, current_input_length);
		}
		else{
			current_input_length = RSA_size(key);
			ret_val = EVP_PKEY_decrypt(pkey_ctx, NULL, &current_processed_length, input + processed_input_length, current_input_length);
		}
		GOTO_CHECK_RET_VAL_CONDITION(ret_val <= 0, FAIL_ProcessFileWithRSA_3);

		// Allocate or reallocate memory
		if (processed == NULL){
			processed = (uchar *)malloc(current_processed_length * sizeof(uchar));
			processed_length = current_processed_length;
		}
		else{
			processed = (uchar *)realloc(processed, (processed_length + current_processed_length) * sizeof(uchar));
			processed_length += current_processed_length;
		}
		GOTO_CHECK_RET_VAL_NOT_EQUAL(processed, NULL, FAIL_ProcessFileWithRSA_3);

		// Effective encryption
		if (is_encryption){
			ret_val = EVP_PKEY_encrypt(pkey_ctx, processed + processed_length - current_processed_length, &current_processed_length, input + processed_input_length, current_input_length);
		}
		else{
			ret_val = EVP_PKEY_decrypt(pkey_ctx, processed + processed_length - current_processed_length, &current_processed_length, input + processed_input_length, current_input_length);
		}
		GOTO_CHECK_RET_VAL_CONDITION(ret_val <= 0, FAIL_ProcessFileWithRSA_4);
		processed_input_length += current_input_length;

	} while (processed_input_length < input_length);

	// Dump processed to file
	ret_val = dump_to_file(output_filename, processed, processed_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_ProcessFileWithRSA_4);

	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_ProcessFileWithRSA_4:
		free(processed);
	FAIL_ProcessFileWithRSA_3:
		free(input);
	FAIL_ProcessFileWithRSA_2:
		EVP_PKEY_CTX_free(pkey_ctx);
	FAIL_ProcessFileWithRSA_1:
		EVP_PKEY_free(evp_key);

	// Return
	return is_error;

}

#pragma endregion

#pragma region ExportedFunction

int EncryptFileWithAES256CBC(const char *input_filename, const char *ciphertext_filename, const char *key_filename) {

	// Return
	return ProcessFileWithAES256CBC(input_filename, ciphertext_filename, 0, key_filename, OperationType_Encryption);

}

RSA *GenerateRSAKeyPair(int bit_length, int tried_public_exponent, const char *passcode, int passcode_length, const char *private_key_filename, const char *public_key_filename){

	RSA *key = NULL;

	// Check given public exponent to be odd
	if (tried_public_exponent % 2 == 0)
		tried_public_exponent++;

	// Generate keys
	key = RSA_generate_auto_key(tried_public_exponent, bit_length);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, NULL);

	// Export keys
	RSA_write_encrypted_keys(key, passcode, passcode_length, public_key_filename, private_key_filename);

	// Return
	return key;

}


int EncryptFileWithRSA(const char *input_filename, const char *output_filename, RSA *key){

	// Return
	return _ProcessFileWithRSA(input_filename, output_filename, key, 1);

}

int DecryptFileWithRSA(const char *input_filename, const char *output_filename, RSA *key){

	// Return
	return _ProcessFileWithRSA(input_filename, output_filename, key, 0);

}

#pragma endregion