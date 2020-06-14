#pragma region IncludedHeaders

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include "FH4_Internals.h"
#include "UTL_Input.h"
#include "UTL_Output.h"
#include "UTL_Macros.h"

#pragma endregion

#pragma region InternalFunctions

int _GenerateMasterComponents(const char *password, size password_length, const uchar *salt, const uchar *master_iv, const uchar *master_key){

	SHA256_CTX sha256_ctx;
	uchar hash[SHA256_DIGEST_LENGTH];
	uchar *hashed = NULL;
	int i;

	// Allocate memory
	hashed = (uchar*)malloc((password_length + SALT_LENGTH)  *sizeof(uchar));
	RETURN_CHECK_RET_VAL_NOT_EQUAL(hashed, NULL, -1);

	// Compute hash
	SHA256_Init(&sha256_ctx);
	for (i = 0; i < HASHING_ROUNDS; i++){

		// Initialize hashing mechanism
		if (i == 0){
			memcpy(hashed, password, password_length);
			memcpy(hashed + password_length, salt, SALT_LENGTH);
			SHA256_Update(&sha256_ctx, hashed, password_length + SALT_LENGTH);
		}
		else{
			memcpy(hashed, hash, SHA256_DIGEST_LENGTH);
			SHA256_Update(&sha256_ctx, hashed, SHA256_DIGEST_LENGTH);
		}

		// Get hash
		SHA256_Final(hash, &sha256_ctx);

	}

	// Save results
	memcpy(master_iv, hash, TRIPLE_DES_CBC_IV_LENGTH);
	memcpy(master_key, hash + TRIPLE_DES_CBC_IV_LENGTH, TRIPLE_DES_CBC_KEY_LENGTH);

	// Free memory
	free(hashed);

	// Return
	return 0;

}

int _EncryptTripleDES(const uchar *plaintext, size plaintext_length, uchar **ciphertext, size *ciphertext_length, const uchar *iv, const uchar *key){

	EVP_CIPHER_CTX *evp_ctx = NULL;
	size allocated_ciphertext_length, returned_length, total_length = 0;
	int ret_val, is_error = -1;

	// Allocate memory
	allocated_ciphertext_length = TRIPLE_DES_CBC_BLOCK_SIZE + plaintext_length;
	if (plaintext_length % TRIPLE_DES_CBC_BLOCK_SIZE != 0)
		allocated_ciphertext_length += TRIPLE_DES_CBC_BLOCK_SIZE - plaintext_length % TRIPLE_DES_CBC_BLOCK_SIZE;
	*ciphertext = (uchar*)malloc(allocated_ciphertext_length  *sizeof(uchar));
	RETURN_CHECK_RET_VAL_NOT_EQUAL(*ciphertext, NULL, -1);

	// Encrypt with Triple DES
	evp_ctx = EVP_CIPHER_CTX_new();
	GOTO_CHECK_RET_VAL_NOT_EQUAL(evp_ctx, NULL, FAIL_EncryptTripleDES_1);
	ret_val = EVP_EncryptInit_ex(evp_ctx, EVP_des_ede3_cbc(), NULL, key, iv);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_EncryptTripleDES_2);
	ret_val = EVP_EncryptUpdate(evp_ctx, *ciphertext, &returned_length, plaintext, plaintext_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_EncryptTripleDES_2);
	total_length += returned_length;
	ret_val = EVP_EncryptFinal_ex(evp_ctx, *ciphertext + total_length, &returned_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_EncryptTripleDES_2);
	total_length += returned_length;

	// Save results
	*ciphertext_length = total_length;
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_EncryptTripleDES_2:
		EVP_CIPHER_CTX_free(evp_ctx);
	FAIL_EncryptTripleDES_1:
		if (is_error){
			free(*ciphertext);
			*ciphertext = NULL;
		}

	// Return
	return is_error;

}

int _DecryptTripleDES(const uchar *ciphertext, size ciphertext_length, uchar **plaintext, size *plaintext_length, const uchar *iv, const uchar *key){

	EVP_CIPHER_CTX *evp_ctx = NULL;
	size returned_length, total_length = 0;
	int ret_val, is_error = -1;

	// Allocate memory
	*plaintext = (uchar *)malloc(ciphertext_length *sizeof(uchar));
	RETURN_CHECK_RET_VAL_NOT_EQUAL(*plaintext, NULL, -1);

	// Decrypt with Triple DES
	evp_ctx = EVP_CIPHER_CTX_new();
	GOTO_CHECK_RET_VAL_NOT_EQUAL(evp_ctx, NULL, FAIL_DecryptTripleDES_1);
	ret_val = EVP_DecryptInit_ex(evp_ctx, EVP_des_ede3_cbc(), NULL, key, iv);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_DecryptTripleDES_2);
	ret_val = EVP_DecryptUpdate(evp_ctx, *plaintext, &returned_length, ciphertext, ciphertext_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_DecryptTripleDES_2);
	total_length += returned_length;
	ret_val = EVP_DecryptFinal_ex(evp_ctx, *plaintext + total_length, &returned_length);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 1, FAIL_DecryptTripleDES_2);
	total_length += returned_length;
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_DecryptTripleDES_2:
		EVP_CIPHER_CTX_free(evp_ctx);
	FAIL_DecryptTripleDES_1:
		if (is_error){
			free(*plaintext);
			*plaintext = NULL;
		}

	// Save results
	*plaintext_length = total_length;

	// Return
	return is_error;

}

#pragma endregion

#pragma region ExportedFunctions

int Encrypt(const char *plaintext, size plaintext_length, const char *password, size password_length, const char *output_filename){

	uchar salt[SALT_LENGTH], iv[TRIPLE_DES_CBC_IV_LENGTH], key[TRIPLE_DES_CBC_KEY_LENGTH], master_iv[TRIPLE_DES_CBC_IV_LENGTH], master_key[TRIPLE_DES_CBC_KEY_LENGTH], inner_plaintext[SHA256_DIGEST_LENGTH];
	uchar *first_ciphertext = NULL,  *second_ciphertext = NULL,  *all_data = NULL;
	size first_ciphertext_length, second_ciphertext_length, total_data_length;
	int ret_val, is_error = -1;

	// Generate salt, actual IV and key
	RAND_bytes(salt, SALT_LENGTH);
	RAND_bytes(iv, TRIPLE_DES_CBC_IV_LENGTH);
	RAND_bytes(key, TRIPLE_DES_CBC_KEY_LENGTH);

	// Generate master IV and key
	ret_val = _GenerateMasterComponents(password, password_length, salt, master_iv, master_key);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, -1);

	// Encrypt generated IV and key with master ones
	memcpy(inner_plaintext, iv, TRIPLE_DES_CBC_IV_LENGTH);
	memcpy(inner_plaintext + TRIPLE_DES_CBC_IV_LENGTH, key, TRIPLE_DES_CBC_KEY_LENGTH);
	ret_val = _EncryptTripleDES(inner_plaintext, SHA256_DIGEST_LENGTH, &first_ciphertext, &first_ciphertext_length, master_iv, master_key);
	RETURN_CHECK_RET_VAL_EQUAL(ret_val, 0, -1);

	// Encrypt plaintext with generated IV and key
	ret_val = _EncryptTripleDES(plaintext, plaintext_length, &second_ciphertext, &second_ciphertext_length, iv, key);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_Encrypt_2);

	// Dump result to file
	total_data_length = SALT_LENGTH + first_ciphertext_length + second_ciphertext_length;
	all_data = (uchar *)malloc(total_data_length * sizeof(uchar));
	GOTO_CHECK_RET_VAL_NOT_EQUAL(all_data, NULL, FAIL_Encrypt_3);
	memcpy(all_data, salt, SALT_LENGTH);
	memcpy(all_data + SALT_LENGTH, first_ciphertext, first_ciphertext_length);
	memcpy(all_data + SALT_LENGTH + first_ciphertext_length, second_ciphertext, second_ciphertext_length);
	dump_to_file(output_filename, all_data, total_data_length);
	
	// Mark function as successful
	is_error = 0;

	// Free memeory
	free(all_data);
	FAIL_Encrypt_3:
		// free(second_ciphertext);
	FAIL_Encrypt_2:
		// free(first_ciphertext);

	// Return
	return is_error;

}

char *Decrypt(const char *ciphertext_filename, const char *password, size password_length, size *plaintext_length){

	uchar master_iv[TRIPLE_DES_CBC_IV_LENGTH], master_key[TRIPLE_DES_CBC_KEY_LENGTH];
	uchar *ciphertext = NULL, *first_plaintext = NULL, *plaintext = NULL;
	size ciphertext_length, first_plaintext_length;
	int ret_val;

	// Read ciphertext from file and get needed components
	ciphertext = read_file_content(ciphertext_filename, &ciphertext_length);
	RETURN_CHECK_RET_VAL_NOT_EQUAL(ciphertext, NULL, NULL);

	// Generate master IV and key from password and salt
	ret_val = _GenerateMasterComponents(password, password_length, ciphertext, master_iv, master_key);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_Decrypt);

	// Decrypt generated IV and key
	ret_val = _DecryptTripleDES(ciphertext + SALT_LENGTH, FIRST_ENCRYPTION_LENGTH, &first_plaintext, &first_plaintext_length, master_iv, master_key);
	GOTO_CHECK_RET_VAL_EQUAL(ret_val, 0, FAIL_Decrypt);

	// Decrypt plaintext with generated IV and key
	_DecryptTripleDES(ciphertext + SALT_LENGTH + FIRST_ENCRYPTION_LENGTH, ciphertext_length - SALT_LENGTH - FIRST_ENCRYPTION_LENGTH, &plaintext, plaintext_length, first_plaintext, first_plaintext + TRIPLE_DES_CBC_IV_LENGTH);

	// Free memory
	FAIL_Decrypt:
		free(ciphertext);

	// Return
	return plaintext;

}

#pragma endregion