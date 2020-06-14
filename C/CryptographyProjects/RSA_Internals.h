#ifndef _RSA_ELEMENTS_H

#define _RSA_ELEMENTS_H

#pragma region IncludedHeaders

#include <openssl/bn.h>
#include <openssl/rsa.h>

#pragma endregion

#pragma region Types

typedef unsigned int size;
typedef unsigned char uchar;

#pragma endregion

#pragma region Configuration

#define PRIMES_BITLENGTH 512
#define KEY_SIZE 2048
#define BLOCK_SIZE 256

#pragma endregion

#pragma region GenerateKeyPairFunctions

RSA *RSA_generate_manual_key(int public_exponent);
RSA *RSA_generate_auto_key(int public_exponent, int bit_length);

#pragma endregion

#pragma region BlockEncryptionDecryption

uchar *RSA_encrypt(RSA *key, const uchar *plaintext, size length, int *ciphertext_length);
uchar *RSA_decrypt(RSA *key, const uchar *ciphertext, size length);

#pragma endregion

#pragma region Getters

int RSA_get_private_exponent(RSA *key, uchar *saved_d);

#pragma endregion

#endif