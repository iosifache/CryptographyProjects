#pragma region IncludedHeaders

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include "FH2_Internals.h"
#include "RSA_Internals.h"
#include "RSA_Input.h"
#include "UTL_Crypto.h"
#include "UTL_Input.h"
#include "UTL_Output.h"
#include "UTL_Macros.h"
#include "UTL_Types.h"

#pragma endregion

#pragma region InternalFunctions

int _DerivePasswordFromInput(uchar *generated_password, size generated_password_length, const uchar *salt, size salt_length, int iterations){

	char *password = NULL;
	size password_length;
	int ret_val;

	// Read password from input
	password = read_from_stdin("[?] Password is: ", &password_length);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(password, NULL, -1);

	// Generate password with PBKDF
	ret_val = PKCS5_PBKDF2_HMAC_SHA1(password, password_length, salt, salt_length, iterations, generated_password_length, generated_password);

	// Free memory
	free(password);

	// Return
	return (ret_val == 1) ? 0 : 1;

}

int _GetAuthTagForFile(const char *filename, const uchar *password, const uchar *iv, uchar *tag){

	EVP_CIPHER_CTX *aes_ctx = NULL;
	uchar *content = NULL,  *ciphertext = NULL;
	size expected_ciphertext_length, ciphertext_length, content_length;
	int is_error = 1;

	// Read content of file
	content = read_file_content(filename, &content_length);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(content, NULL, -1);

	// Allocate memory
	expected_ciphertext_length = content_length;
	if (content_length % AES_256_GCM_KEY_SIZE != 0)
		expected_ciphertext_length += AES_256_GCM_KEY_SIZE - expected_ciphertext_length % AES_256_GCM_KEY_SIZE;
	ciphertext = (uchar *)malloc(expected_ciphertext_length * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(ciphertext, NULL, FAIL_GetAuthTagForFile_1);

	// Init context, the IV and key
	aes_ctx = EVP_CIPHER_CTX_new();
	GOTO_CHECK_RET_VAL_NOT_EQUAL(aes_ctx, NULL, FAIL_GetAuthTagForFile_2);
	EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_AEAD_SET_IVLEN, AES_256_GCM_IV_SIZE, NULL);
	EVP_EncryptInit_ex(aes_ctx, NULL, NULL, password, iv);

	// Encrypt content
	EVP_EncryptUpdate(aes_ctx, ciphertext, &ciphertext_length, content, content_length);
	EVP_EncryptFinal_ex(aes_ctx, ciphertext, &ciphertext_length);

	// Get auth tag
	EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_AEAD_GET_TAG, AES_256_GCM_TAG_SIZE, tag);

	// Mark function as successful
	is_error = 0;

	// Free memory
	EVP_CIPHER_CTX_free(aes_ctx);
	FAIL_GetAuthTagForFile_2:
		free(ciphertext);
	FAIL_GetAuthTagForFile_1:
		free(content);

	// Return
	return is_error;

}

int _GetMAC(const char *key_filename, const uchar *tag, uchar *encrypted_tag){

	RSA *key;
	int ret_val, is_error = 1;

	// Read RSA private key
	key = RSA_read_private_key(key_filename, NULL, 0);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, -1);

	// Encrypt the tag
	ret_val = RSA_private_encrypt(RSA_3072_BLOCK_SIZE, tag, encrypted_tag, key, RSA_NO_PADDING);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(ret_val, -1, FAIL_GenerateMAC_1);
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_GenerateMAC_1:
		RSA_free(key);

	// Return
	return is_error;

}

int _DecryptTag(const char *public_key_filename, const uchar *encrypted_tag, uchar *decrypted_tag){

	RSA *key;
	int ret_val, is_error = 1;

	// Read RSA private key
	key = RSA_read_public_key(public_key_filename);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(key, NULL, -1);

	// Encrypt the tag
	ret_val = RSA_public_decrypt(RSA_3072_BLOCK_SIZE, encrypted_tag, decrypted_tag, key, RSA_NO_PADDING);
	GOTO_CHECK_RET_VAL_NOT_EQUAL(ret_val, -1, FAIL_DecryptTag_1);
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_DecryptTag_1:
		RSA_free(key);

	// Return
	return is_error;

}

#pragma endregion

#pragma region ExportedFunctions

int GenerateMAC(const char *document_filename, const char *private_key_filename, const char *mac_filename){

	uchar generated_password[AES_256_GCM_KEY_SIZE], salt[SALT_SIZE], tag[RSA_3072_BLOCK_SIZE], encrypted_tag[RSA_3072_BLOCK_SIZE], dumped[SALT_SIZE + RSA_3072_BLOCK_SIZE];
	int ret_val;

	// Generate random salt
	RAND_bytes(salt, SALT_SIZE);

	// Read password and generate random
	ret_val = _DerivePasswordFromInput(generated_password, AES_256_GCM_KEY_SIZE, salt, SALT_SIZE, PBKDF_HASH_ITERATION);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, 1);

	// Generate the tag
	ret_val = _GetAuthTagForFile(document_filename, generated_password, salt, tag);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, 1);

	// Pad the buffer
	pkcs1_pad(tag, AES_256_GCM_KEY_SIZE, RSA_3072_BLOCK_SIZE);

	// Get MAC
	ret_val = _GetMAC(private_key_filename, tag, encrypted_tag);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, 1);

	// Dump salt and encrypted tag to file
	memcpy(dumped, salt, SALT_SIZE);
	memcpy(dumped + SALT_SIZE, encrypted_tag, RSA_3072_BLOCK_SIZE);
	ret_val = dump_to_file(mac_filename, dumped, SALT_SIZE + RSA_3072_BLOCK_SIZE);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, 1);

	// Return
	return 0;

}

int CheckMAC(const char *document_filename, const char *public_key_filename, const char *mac_filename){

	uchar generated_password[AES_256_GCM_KEY_SIZE], salt[SALT_SIZE], tag[RSA_3072_BLOCK_SIZE], decrypted_tag[RSA_3072_BLOCK_SIZE], mac[RSA_3072_BLOCK_SIZE];
	uchar *content;
	size content_length;
	int ret_val;

	// Read content of MAC file and copy salt and real MAC
	content = read_file_content(mac_filename, &content_length);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(content, NULL, -1);
	memcpy(salt, content, SALT_SIZE);
	memcpy(mac, content + SALT_SIZE, RSA_3072_BLOCK_SIZE);
	free(content);

	// Decrypt tag
	ret_val = _DecryptTag(public_key_filename, mac, decrypted_tag);

	// Unpad the MAC
	ret_val = pkcs1_unpad(decrypted_tag, RSA_3072_BLOCK_SIZE);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(ret_val, -1, 1);

	// Read password and generate random
	ret_val = _DerivePasswordFromInput(generated_password, AES_256_GCM_KEY_SIZE, salt, SALT_SIZE, PBKDF_HASH_ITERATION);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, 1);

	// Generate the tag
	ret_val = _GetAuthTagForFile(document_filename, generated_password, salt, tag);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, 1);

	// Compare tags and return
	if (memcmp(tag, decrypted_tag, AES_256_GCM_TAG_SIZE) == 0)
		return 0;
	else
		return 1;

}

#pragma endregion