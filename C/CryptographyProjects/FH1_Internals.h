#ifndef _FH1_INTERNALS_H

#define _FH1_INTERNALS_H

#pragma region IncludedHeaders

#include <openssl/rsa.h>

#pragma endregion

#pragma region Defines

#define RSA_OAEP_PADDING_LENGTH 66

#pragma endregion

#pragma region ExportedFunctions

int EncryptFileWithAES256CBC(const char *input_filename, const char *ciphertext_filename, const char *key_filename);
RSA *GenerateRSAKeyPair(int bit_length, int tried_public_exponent, const char *passcode, int passcode_length, const char *private_key_filename, const char *public_key_filename);
int EncryptFileWithRSA(const char *input_filename, const char *output_filename, RSA *key);
int DecryptFileWithRSA(const char *input_filename, const char *output_filename, RSA *key);

#pragma endregion

#endif