#pragma region IncludedHeaders

#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "AiG_Elements.h"
#include "UTL_Math.h"

#pragma endregion

#pragma region Defines

#define POLYNOM_LENGTH 16
#define R_FIRST_BYTE 0xe1

#pragma endregion

#pragma region GlobalVariables

char *hash_subkey = NULL;
char *key = NULL;

#pragma endregion

#pragma region ByteOperations

void _IncrementLast4BytesFrom16BytesBlock(uchar *x){

	uint val;

	val = BITOP_CONVERT_MEMORY_TO_UINT(x + AES_BLOCK_SIZE - 4);
	val++;
	BITOP_PLACE_UINT_TO_MEMORY(x + AES_BLOCK_SIZE - 4, val);

}

void _DecrementLast4BytesFrom16BytesBlock(uchar *x){

	uint val;

	val = BITOP_CONVERT_MEMORY_TO_UINT(x + AES_BLOCK_SIZE - 4);
	val--;
	BITOP_PLACE_UINT_TO_MEMORY(x + AES_BLOCK_SIZE - 4, val);

}

void _ShiftRight16BytesBlock(uchar *x){

	uchar possible_overflow, intermediate_overflow;
	uint value;

	// Shift first chunk and get last bit
	possible_overflow = BITOP_GET_BIT(x[3], 0);
	value = BITOP_CONVERT_MEMORY_TO_UINT(x);
	value >>= 1;
	BITOP_PLACE_UINT_TO_MEMORY(x, value);

	// Shift first chunk, append saved bit and get the last one
	intermediate_overflow = BITOP_GET_BIT(x[7], 0);
	value = BITOP_CONVERT_MEMORY_TO_UINT(x + 4);
	value >>= 1;
	BITOP_PLACE_UINT_TO_MEMORY(x + 4, value);
	if (intermediate_overflow)
		BITOP_SET_BIT(x[4], 7);
	possible_overflow = intermediate_overflow;

	// Shift first chunk, append saved bit and get the last one
	intermediate_overflow = BITOP_GET_BIT(x[11], 0);
	value = BITOP_CONVERT_MEMORY_TO_UINT(x + 8);
	value >>= 1;
	BITOP_PLACE_UINT_TO_MEMORY(x + 8, value);
	if (intermediate_overflow)
		BITOP_SET_BIT(x[8], 7);
	possible_overflow = intermediate_overflow;

	// Shift first chunk, append saved bit and get the last one
	value = BITOP_CONVERT_MEMORY_TO_UINT(x + 12);
	value >>= 1;
	BITOP_PLACE_UINT_TO_MEMORY(x + 12, value);
	if (intermediate_overflow)
		BITOP_SET_BIT(x[12], 7);

}

void _XOR16BytesBlocks(const uchar *x, const uchar *y, uchar *result){

	int i;

	// Interate
	for (i = 0; i < BLOCK_SIZE; i++){
		result[i] = x[i] ^ y[i];
	}

}

#pragma endregion

#pragma region GaloisFieldMathOperations

void _MultiplyPolynoms(const uchar *x, const uchar *y, uchar *result){

	uchar v[POLYNOM_LENGTH];
	uchar *z;
	int i, j;

	// Init Z
	z = result;
	memset(z, 0, POLYNOM_LENGTH);

	// Init V
	memcpy(v, y, POLYNOM_LENGTH);

	// Iterate
	for (i = 0; i < POLYNOM_LENGTH; i++){
		for (j = 0; j < 8; j++){

			// Update Z
			if (BITOP_GET_BIT(x[i], j) == 1){
				_XOR16BytesBlocks(z, v, z);
			}

			// Update V
			_ShiftRight16BytesBlock(v);
			if (BITOP_GET_BIT(v[POLYNOM_LENGTH - 1], 0) == 1)

				// XOR with R, that has only the first byte non-zero
				v[0] ^= R_FIRST_BYTE;
				
		}
	}

}

#pragma endregion

#pragma region InternalFunctions

int _InitHashSubkey(){

	AES_KEY aes_enc_key;
	char plain_hash_subkey[AES_BLOCK_SIZE] = {'\0'};
	int ret_val;

	// Verify key
	if (key == NULL)
		return -1;

	// Allocate hash subkey
	hash_subkey = (uchar *)malloc(AES_BLOCK_SIZE * sizeof(uchar));
	if (hash_subkey == NULL)
		return -1;

	// Set AES encrypt key
	ret_val = AES_set_encrypt_key(key, 8 * AES_BLOCK_SIZE, &aes_enc_key);
	if (ret_val){
		free(hash_subkey);
		return -1;
	}

	// Encrypt
	AES_encrypt(plain_hash_subkey, hash_subkey, &aes_enc_key);

	// Return
	return 0;

}

int _GenerateJ(const uchar *iv, char *j){

	// Considering only the recommended length for IV, namely 96 bits, generate J
	memcpy(j, iv, IV_RECOMMENDED_LENGTH);
	memset(j + IV_RECOMMENDED_LENGTH, 0, BLOCK_SIZE - IV_RECOMMENDED_LENGTH);

	// Return
	return 0;

}

int _GenerateGHASH(const uchar *x, size length, char *ghash){

	uchar xor_result[BLOCK_SIZE], multiplication_result[BLOCK_SIZE];
	int i;

	// Check requirements
	if (length % BLOCK_SIZE != 0 || hash_subkey == NULL)
		return -1;

	// Init Y, in this context ghash
	memset(ghash, 0, BLOCK_SIZE);

	// Iterate
	for (i = 0; i < length / BLOCK_SIZE; i++){

		// Compute new Y
		_XOR16BytesBlocks(ghash, x + i * BLOCK_SIZE, xor_result);
		_MultiplyPolynoms(xor_result, hash_subkey, multiplication_result);
		memcpy(ghash, multiplication_result, BLOCK_SIZE);

	}

	// Return
	return 0;

}

int _GenerateGCTR(const uchar *x, size x_length, const uchar *icb, uchar *gctr){

	AES_KEY aes_enc_key;
	uchar cb[AES_BLOCK_SIZE], enc_cb[AES_BLOCK_SIZE], xor_result[BLOCK_SIZE];
	int chunks_count, i;

	// Verify requirements
	if (x == NULL || x_length == 0 || key == NULL)
		return -1;

	// Get number of chuncks
	chunks_count = ceil((double)x_length / BLOCK_SIZE);

	// Init CB
	memcpy(cb, icb, AES_BLOCK_SIZE);

	// Init AES
	AES_set_encrypt_key(key, 8 * AES_BLOCK_SIZE, &aes_enc_key);

	// Iterate
	for (i = 0; i < chunks_count - 1; i++){
		
		// Encrypt CB
		AES_encrypt(cb, enc_cb, &aes_enc_key);

		// Multiply polynoms
		_XOR16BytesBlocks(x + i * BLOCK_SIZE, enc_cb, xor_result);
		memcpy(gctr + i * BLOCK_SIZE, xor_result, AES_BLOCK_SIZE);

		// Increment CB
		_IncrementLast4BytesFrom16BytesBlock(cb);

	}

	// Prepare the GCTR result
	AES_encrypt(cb, enc_cb, &aes_enc_key);
	_XOR16BytesBlocks(x + (chunks_count - 1) * BLOCK_SIZE, enc_cb, xor_result);
	memcpy(gctr + (chunks_count - 1) * BLOCK_SIZE, xor_result, BLOCK_SIZE);

	// Return Y
	return 0;

}

int _GenerateGHASHForDataAndAAD(const uchar *data, size data_length, const uchar *aad, size aad_length, uchar *ghash, size *ghash_length){

	uchar s[BLOCK_SIZE];
	uchar *s_init;
	size s_init_pos = 0;
	int u, v, ret_val;

	// Compute u and v
	u = BLOCK_SIZE * ceil((double)data_length / BLOCK_SIZE) - data_length;
	v = BLOCK_SIZE * ceil((double)aad_length / BLOCK_SIZE) - aad_length;

	// Generate S
	s_init = (uchar*)malloc((aad_length + v + data_length + u + 2 * sizeof(size)) * sizeof(uchar));
	if (s_init == NULL)
		return -1;
	memcpy(s_init, aad, aad_length);
	s_init_pos += aad_length;
	memset(s_init + s_init_pos, 0, v);
	s_init_pos += v;
	memcpy(s_init + s_init_pos, data, data_length);
	s_init_pos += data_length;
	memset(s_init + s_init_pos, 0, u);
	s_init_pos += u;
	memcpy(s_init + s_init_pos, &aad_length, sizeof(size));
	s_init_pos += sizeof(size);
	memcpy(s_init + s_init_pos, &data_length, sizeof(size));
	s_init_pos += sizeof(size);
	ret_val = _GenerateGHASH(s_init, s_init_pos, s);
	free(s_init);
	if (ret_val != 0){
		return -1;
	}

	// Save
	memcpy(ghash, s, BLOCK_SIZE);
	*ghash_length = s_init_pos;

	// Return
	return 0;

}

int _ApplyGenericGCM(const uchar *in, size in_length, const uchar* aad, size aad_length, const uchar* iv, size tag_length, uchar *out, uchar *auth_tag, GCM_MODE mode){

	uchar j[BLOCK_SIZE], s[BLOCK_SIZE];
	uchar *c = NULL, *t = NULL, *data = NULL;
	size s_length;
	int ret_val;

	// Check tag to be one of (128, 120, 112, 104, 96)
	if (tag_length < MIN_TAG_LENGTH || tag_length > MAX_TAG_LENGTH)
		return -1;

	// Init hash suhkey
	if (hash_subkey == NULL){
		ret_val = _InitHashSubkey();
		if (ret_val != 0)
			return -1;
	}

	// Generate J
	_GenerateJ(iv, j);

	// Increment J
	_IncrementLast4BytesFrom16BytesBlock(j);

	// Allocate, generate and save C
	c = (uchar*)malloc(in_length * sizeof(uchar));
	if (c == NULL)
		return -1;
	ret_val = _GenerateGCTR(in, in_length, j, c);
	if (ret_val != 0){
		free(c);
		return -1;
	}

	// Generate S
	if (mode == ENCRYPTION)
		data = c;
	else if (mode == DECRYPTION)
		data = in;
	ret_val = _GenerateGHASHForDataAndAAD(data, in_length, aad, aad_length, s, &s_length);
	if (ret_val != 0){
		free(c);
		return -1;
	}

	// Clear bit and set the first one
	_DecrementLast4BytesFrom16BytesBlock(j);

	// Generate authentification tag
	t = (uchar*)malloc(s_length * sizeof(uchar));
	if (t == NULL){
		free(c);
		free(s);
		return -1;
	}
	ret_val = _GenerateGCTR(s, s_length, j, t);
	if (ret_val != 0){
		free(c);
		return -1;
	}

	// Save
	memcpy(out, c, in_length);
	memcpy(auth_tag, t, tag_length);

	// Free memory
	free(c);
	free(t);

	// Return
	return 0;

}

#pragma endregion

#pragma region InterfaceFunctions

int InitContext(const char *random_key){

	// Allocate key
	key = (uchar *)malloc(AES_BLOCK_SIZE * sizeof(uchar));
	if (key == NULL)
		return -1;

	// Copy key
	memcpy(key, random_key, AES_BLOCK_SIZE);

	// Return
	return 0;

}

void FreeContext(){

	// Free memory
	if (key != NULL)
		free(key);
	if (hash_subkey != NULL)
		free(hash_subkey);

}

int AuthEncryptWithGCM(const uchar *plaintext, size plaintext_length, const uchar *aad, size aad_length, const uchar *iv, size tag_length, uchar *ciphertext, uchar *auth_tag){

	_ApplyGenericGCM(plaintext, plaintext_length, aad, aad_length, iv, tag_length, ciphertext, auth_tag, ENCRYPTION);

}

int AuthDecryptWithGCM(const uchar *ciphertext, size ciphertext_length, const uchar *aad, size aad_length, const uchar *iv, const uchar *auth_tag, size tag_length, uchar *plaintext){

	uchar t[MAX_TAG_LENGTH];
	uchar *p;
	int ret_val;

	// Allocate P
	p = (uchar*)malloc(ciphertext_length * sizeof(uchar));
	if (p == NULL){
		return -1;
	}
	
	// Decrypt
	ret_val = _ApplyGenericGCM(ciphertext, ciphertext_length, aad, aad_length, iv, tag_length, p, t, DECRYPTION);
	if (ret_val != 0){
		free(p);
		return -1;
	}

	// Verify tags
	if (memcmp(t, auth_tag, tag_length) != 0){
		free(p);
		return -1;
	}

	// Save plaintext
	memcpy(plaintext, p, ciphertext_length);

	// Free
	free(p);

	// Return
	return 0;

}

#pragma endregion