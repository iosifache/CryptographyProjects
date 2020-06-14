#pragma region IncludedLibraries

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include "UTL_Crypto.h"
#include "UTL_Input.h"
#include "UTL_Output.h"

#pragma endregion

#pragma region EVPOperations

int ProcessFileWithAES256CBC(const char *input_filename, const char *ciphertext_filename, int are_parameters_readed, const char *key_filename, enum OperationType operation){

	EVP_CIPHER_CTX *evp_ctx = NULL;
	uchar key[AES_256_CBC_KEY_LENGTH], iv[AES_256_CBC_IV_LENGTH], key_file_content[AES_256_CBC_KEY_LENGTH + AES_256_CBC_IV_LENGTH];
	uchar *content = NULL, *processed = NULL, *readed_key_file_content = NULL;
	size content_size, processed_length, effective_processed_length, key_file_content_size;
	int ret_val, is_error = 1, is_encryption;

	// Check if encryption
	is_encryption = (operation == OperationType_Encryption) ? 1 : 0;

	// Read content of input file
	content = read_file_content(input_filename, &content_size);
	if (content == NULL)
		return -1;

	// Allocate memory
	processed_length = content_size;
	if (is_encryption && content_size % AES_256_CBC_KEY_LENGTH != 0)
		processed_length += AES_256_CBC_KEY_LENGTH - content_size % AES_256_CBC_KEY_LENGTH;
	processed = (uchar*)malloc(processed_length * sizeof(uchar));
	if (processed == NULL)
		goto FAIL_FH1_Main_1;

	// Get parameters
	if (are_parameters_readed || !is_encryption){
		
		// Read file and check size
		readed_key_file_content = read_file_content(key_filename, &key_file_content_size);
		if (readed_key_file_content == NULL)
			goto FAIL_FH1_Main_1;
		if (key_file_content_size != AES_256_CBC_KEY_LENGTH + AES_256_CBC_IV_LENGTH)
			goto FAIL_FH1_Main_12;
		
		// Get key and IV
		memcpy(key, readed_key_file_content, AES_256_CBC_KEY_LENGTH);
		memcpy(iv, readed_key_file_content + AES_256_CBC_KEY_LENGTH, AES_256_CBC_IV_LENGTH);

	}
	else{

		// Generate key and IV
		RAND_bytes(key, AES_256_CBC_KEY_LENGTH);
		RAND_bytes(iv, AES_256_CBC_IV_LENGTH);

		// Dump to file
		memcpy(key_file_content, key, AES_256_CBC_KEY_LENGTH);
		memcpy(key_file_content + AES_256_CBC_KEY_LENGTH, iv, AES_256_CBC_IV_LENGTH);
		dump_to_file(key_filename, key_file_content, AES_256_CBC_KEY_LENGTH + AES_256_CBC_IV_LENGTH);

	}

	// Encrypt file with AES-CBC with 256 key bit length
	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx)
		goto FAIL_FH1_Main_2;
	ret_val = (is_encryption) ? EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(), NULL, key, iv) : EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	if (ret_val != 1)
		goto FAIL_FH1_Main_2;
	ret_val = (is_encryption) ? EVP_EncryptUpdate(evp_ctx, processed, &effective_processed_length, content, content_size) : EVP_DecryptUpdate(evp_ctx, processed, &effective_processed_length, content, content_size);
	if (ret_val != 1)
		goto FAIL_FH1_Main_2;
	processed_length = effective_processed_length;
	ret_val = (is_encryption) ? EVP_EncryptFinal(evp_ctx, processed + effective_processed_length, &effective_processed_length) : EVP_DecryptFinal(evp_ctx, processed + effective_processed_length, &effective_processed_length);
	if (ret_val != 1)
		goto FAIL_FH1_Main_2;
	processed_length += effective_processed_length;

	// Dump processed to file
	dump_to_file(ciphertext_filename, processed, processed_length);

	// Mark function as successful
	is_error = 0;

	// Label for failed operations
	EVP_CIPHER_CTX_free(evp_ctx);
	FAIL_FH1_Main_2:
		free(processed);
	FAIL_FH1_Main_12:
		if (readed_key_file_content != NULL)
			free(readed_key_file_content);
	FAIL_FH1_Main_1:
		free(content);

	// Return
	return is_error;

}

#pragma endregion

#pragma region PaddingSchemes

void pkcs1_pad(uchar *buffer, size message_length, size desired_length){

	int i;

	// Copy message on the end of the buffer
	memcpy(buffer + desired_length - message_length, buffer, message_length);

	// Add prefix and separator between random bytes and message 
	buffer[0] = 0;
	buffer[1] = 2;
	buffer[desired_length - message_length - 1] = 0;

	// Complete with non-zero random bytes
	RAND_bytes(buffer + 2, desired_length - message_length - 3);
	for (i = 2; i < desired_length - message_length - 1; i++)
		if (buffer[i] == 0)
			buffer[i]++;

}

int pkcs1_unpad(uchar *buffer, size buffer_length){

	int separator_position;

	// Check prefix
	if (buffer[0] != 0 || buffer[1] != 2)
		return -1;

	// Search separator and check its position
	for (separator_position = 1; separator_position++; separator_position < buffer_length)
		if (buffer[separator_position] == 0)
			break;
	if (separator_position == buffer_length - 1)
		return -1;

	// Remove padding
	memcpy(buffer, buffer + separator_position + 1, buffer_length - separator_position);

	// Return 
	return (buffer_length - separator_position);

}

void pkcs7_pad(uchar *buffer, size length, size multiple_of){

	int actual_strlen, pad_value, i;

	// Verify parameters
	if (length % multiple_of != 0)
		return -1;

	// Get value for padding
	actual_strlen = strlen(buffer);
	pad_value = multiple_of - actual_strlen % multiple_of;

	// Fill with the value
	if (pad_value != 0)
		for (i = actual_strlen; i < length; i++)
			buffer[i] = pad_value;

}

void pkcs7_unpad(uchar *buffer, size length, size multiple_of){

	int flag = 1;
	int possible_padding_value, i;

	// Verify parameters
	if (length % multiple_of != 0)
		return -1;

	// Get padding value
	possible_padding_value = buffer[length - 1];

	// Verify if text is padded
	for (i = length - 2; i > length - possible_padding_value; i--)
		if (buffer[i] != possible_padding_value){
			flag = 0;
			break;
		}

	// Check if padding must be removed
	if (flag == 1)
		for (i = length - 1; i > length - possible_padding_value - 1; i--)
			buffer[i] = '\0';

	// Return
	return 0;

}

#pragma endregion