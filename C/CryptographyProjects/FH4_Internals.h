#ifndef _FH4_INTERNALS_H

#define _FH4_INTERNALS_H

#pragma region IncludedHeaders

#include "UTL_Types.h"

#pragma endregion

#pragma region Defines

#define TRIPLE_DES_CBC_BLOCK_SIZE 8
#define TRIPLE_DES_CBC_IV_LENGTH 8
#define TRIPLE_DES_CBC_KEY_LENGTH 24
#define FIRST_ENCRYPTION_LENGTH 40

#pragma endregion

#pragma region Configuration

#define SALT_LENGTH 32
#define HASHING_ROUNDS 10

#pragma endregion

#pragma region ExportedFunctions

int Encrypt(const char *plaintext, size plaintext_length, const char *password, size password_length, const char *output_filename);
char *Decrypt(const char *ciphertext_filename, const char *password, size password_length, size *plaintext_length);

#pragma endregion

#endif