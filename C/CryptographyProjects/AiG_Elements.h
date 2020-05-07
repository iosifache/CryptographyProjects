#ifndef _AiG_ELEMENTS_H

#define _AiG_ELEMENTS_H

#pragma region Types

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long long size;

#pragma endregion

#pragma region Structures

typedef enum {
	ENCRYPTION = 0,
	DECRYPTION = 1
} GCM_MODE;

#pragma endregion

#pragma region Configuration

#define BLOCK_SIZE 16
#define KEY_SIZE 16
#define IV_RECOMMENDED_LENGTH 12
#define MIN_TAG_LENGTH 12
#define MAX_TAG_LENGTH 16

#pragma endregion

#pragma region ByteOperations

void _ShiftRight16BytesBlock(uchar* x);
void _XOR16BytesBlocks(const uchar* x, const uchar* y, uchar* result);
void _IncrementLast4BytesFrom16BytesBlock(uchar* x);
void _DecrementLast4BytesFrom16BytesBlock(uchar* x);

#pragma endregion

#pragma region GaloisFieldMathOperations

void _MultiplyPolynoms(const uchar *x, const uchar *y, uchar *result);

#pragma endregion

#pragma region InternalFunctions

int _InitHashSubkey();
int _GenerateJ(const uchar* iv, char *j);
int _GenerateGHASH(const uchar *x, size length, char *ghash);
int _GenerateGCTR(const uchar *x, size x_length, const uchar *icb, uchar *gctr);
int _GenerateGHASHForDataAndAAD(const uchar *data, size data_length, const uchar *aad, size aad_length, uchar *ghash, size *ghash_length);
int _ApplyGenericGCM(const uchar *in, size in_length, const uchar* aad, size aad_length, const uchar* iv, size tag_length, uchar *out, uchar* auth_tag, GCM_MODE mode);

#pragma endregion

#pragma region InterfaceFunctions

int InitContext(const char* random_key);
void FreeContext();
int AuthEncryptWithGCM(const uchar *plaintext, size plaintext_length, const uchar *aad, size aad_length, const uchar *iv, size tag_length, uchar *ciphertext, uchar *auth_tag);
int AuthDecryptWithGCM(const uchar *ciphertext, size ciphertext_length, const uchar *aad, size aad_length, const uchar *iv, const uchar *auth_tag, size tag_length, uchar *plaintext);

#pragma endregion

#endif