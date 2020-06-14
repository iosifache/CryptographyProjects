#pragma region IncludedHeaders

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>
#include "FH3_Internals.h"
#include "RSA_Internals.h"
#include "RSA_Input.h"
#include "RSA_Output.h"
#include "UTL_Crypto.h"
#include "UTL_Input.h"
#include "UTL_Output.h"
#include "UTL_Macros.h"

#pragma endregion

#pragma region ExportedFunctions

int ProcessFile(const char *in_filename, const char *parameters_filename, const char *out_filename, enum OperationType operation){

	// Return
	return ProcessFileWithAES256CBC(in_filename, out_filename, 1, parameters_filename, operation);

}

int GenerateRSAKeys(int bit_length, int public_exponent, const char *passcode, int passcode_length, const char *private_key_filename, const char *public_key_filename){

	RSA *key = NULL;

	// Generate RSA keys
	key = RSA_generate_auto_key(public_exponent, bit_length);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, -1);

	// Dump keys
	RSA_write_encrypted_keys(key, passcode, passcode_length, public_key_filename, private_key_filename);

	// Free memory
	RSA_free(key);

	// Return
	return 0;

}

int DumpRSAPrivateKey(const char *private_key_filename, const char *passcode){

	RSA *key = NULL;

	// Read password
	key = RSA_read_private_key(private_key_filename, passcode, strlen(passcode));
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, -1);

	// Dump parameters
	RSA_dump_private_key(key);

	// Free memory
	RSA_free(key);

	// Return
	return 0;

}

int PaddedEncryptFileWithRSA(const char *plaintext_filename, const char *public_key_filename, const char *ciphertext_filename, char padding_value, int minimum_padding_length){

	RSA *key = NULL;
	uchar *plaintext = NULL, *current_block = NULL, *ciphertext = NULL;
	size plaintext_length, processed_plaintext_length, ciphertext_length, current_position_in_plaintext = 0, padding_length, remained_length, block_size;
	int i, ret_val, is_error = 1;

	// Read RSA private key
	key = RSA_read_public_key(public_key_filename);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, -1);

	// Get block size
	block_size = RSA_size(key);

	// Allocate memory
	current_block = (uchar *)malloc(block_size * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(current_block, NULL, FAIL_EncryptFileWithRSA_1);

	// Read content of file
	plaintext = read_file_content(plaintext_filename, &plaintext_length);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(plaintext, NULL, FAIL_EncryptFileWithRSA_2);

	// Split file in blocks
	while (current_position_in_plaintext < plaintext_length){

		// Get current block with padding included
		remained_length = plaintext_length - current_position_in_plaintext;
		if (remained_length > block_size){
			padding_length = minimum_padding_length;
			processed_plaintext_length = block_size - minimum_padding_length;
		}
		else{
			padding_length = block_size - remained_length;
			processed_plaintext_length = remained_length;
		}
		memset(current_block, padding_value, padding_length); 
		memcpy(current_block + padding_length, plaintext + current_position_in_plaintext, processed_plaintext_length);

		// Encrypt current block
		if (ciphertext == NULL){
			ciphertext = (uchar *)malloc(block_size * sizeof(uchar));
			ciphertext_length = block_size;
		}
		else{
			ciphertext = (uchar *)realloc(ciphertext, (block_size + ciphertext_length) * sizeof(uchar));
			ciphertext_length += block_size;
		}
		ret_val = RSA_public_encrypt(block_size, current_block, ciphertext + ciphertext_length - block_size, key, RSA_NO_PADDING);
		if (ret_val == -1)
			goto FAIL_EncryptFileWithRSA_3;

		// Increment position in plaintext buffer
		current_position_in_plaintext += processed_plaintext_length;

	}

	// Dump ciphertext to file
	ret_val = dump_to_file(ciphertext_filename, ciphertext, ciphertext_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_EncryptFileWithRSA_3);
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_EncryptFileWithRSA_3:
		RSA_free(key);
	FAIL_EncryptFileWithRSA_2:
		free(plaintext);
	FAIL_EncryptFileWithRSA_1:
		free(current_block);

	// Return
	return is_error;

}

int ComputeRSAAuthInfo(const char *in_filename, const char *private_key_filename, const char *passcode, int passcode_length, const char *auth_filename){

	EVP_CIPHER_CTX *aes_ctx = NULL;
	RSA *private_key = NULL;
	BIGNUM *d = NULL;
	uchar iv[AES_128_CBC_IV_LENGTH], key[AES_128_CBC_KEY_LENGTH], mac[AES_128_CBC_BLOCK_SIZE];
	uchar *content = NULL, *d_bin = NULL, *encrypted_content = NULL, *auth_info = NULL;
	size content_size, block_size, processed_length, effective_processed_length;
	int ret_val, is_error = 1;

	// Read file content
	content = read_file_content(in_filename, &content_size);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(content, NULL, -1);

	// Allocate memory
	processed_length = content_size;
	if (content_size % AES_128_CBC_KEY_LENGTH != 0)
		processed_length += AES_128_CBC_KEY_LENGTH - content_size % AES_128_CBC_KEY_LENGTH;
	encrypted_content = (uchar *)malloc(processed_length * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(encrypted_content, NULL, FAIL_ComputeRSAAuthInfo_1);

	// Read key
	private_key = RSA_read_private_key(private_key_filename, passcode, passcode_length);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(private_key, NULL, FAIL_ComputeRSAAuthInfo_2);

	// Get block size
	block_size = RSA_size(private_key);

	// Get private exponent, IV and key
	d_bin = (uchar *)malloc(block_size * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(d_bin, NULL, FAIL_ComputeRSAAuthInfo_2);
	ret_val = RSA_get_private_exponent(private_key, d_bin);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_ComputeRSAAuthInfo_3);
	memcpy(iv, d_bin, AES_128_CBC_IV_LENGTH);
	memcpy(key, d_bin + AES_128_CBC_IV_LENGTH, AES_128_CBC_KEY_LENGTH);

	// Encrypt file with AES-128-CBC to get the last encrypted block
	aes_ctx = EVP_CIPHER_CTX_new();
	GOTO_CHECK_RET_VAL_NOT_EQUAL(aes_ctx, NULL, FAIL_ComputeRSAAuthInfo_3);
	ret_val = EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_cbc(), NULL, key, iv);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_ComputeRSAAuthInfo_4);
	ret_val = EVP_EncryptUpdate(aes_ctx, encrypted_content, &effective_processed_length, content, content_size);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_ComputeRSAAuthInfo_4);
	processed_length = effective_processed_length;
	ret_val = EVP_EncryptFinal(aes_ctx, encrypted_content + effective_processed_length, &effective_processed_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_ComputeRSAAuthInfo_4);
	processed_length += effective_processed_length;
	
	// Get MAC
	memcpy(mac, encrypted_content + effective_processed_length - AES_128_CBC_BLOCK_SIZE, AES_128_CBC_BLOCK_SIZE);

	// Compute auth info
	auth_info = (uchar *)malloc(block_size * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(auth_info, NULL, FAIL_ComputeRSAAuthInfo_4);
	RSA_private_decrypt(AES_128_CBC_BLOCK_SIZE, mac, auth_info, private_key, RSA_PKCS1_OAEP_PADDING);

	// Dump auth info to file
	ret_val = dump_to_file(auth_filename, auth_info, block_size);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_ComputeRSAAuthInfo_4);
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_ComputeRSAAuthInfo_4:
		EVP_CIPHER_CTX_free(aes_ctx);
	FAIL_ComputeRSAAuthInfo_3:
		free(d_bin);
	FAIL_ComputeRSAAuthInfo_2:
		free(encrypted_content);
	FAIL_ComputeRSAAuthInfo_1:
		free(content);

	// Return
	return is_error;

}

#pragma endregion