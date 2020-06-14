#ifndef _FH3_INTERNALS_H

#define _FH3_INTERNALS_H

#pragma region IncludedHeaders

#include "UTL_Enumerations.h"

#pragma endregion

#pragma region Defines

#define AES_128_CBC_IV_LENGTH 16
#define AES_128_CBC_KEY_LENGTH 16
#define AES_128_CBC_BLOCK_SIZE 16

#pragma endregion

#pragma region ExportedFunctions

int ProcessFile(const char *in_filename, const char *parameters_filename, const char *out_filename, enum OperationType operation);
int GenerateRSAKeys(int bit_length, int public_exponent, const char *passcode, int passcode_length, const char *private_key_filename, const char *public_key_filename);
int DumpRSAPrivateKey(const char *private_key_filename, const char *passcode);
int PaddedEncryptFileWithRSA(const char *plaintext_filename, const char *public_key_filename, const char *ciphertext_filename, char padding_value, int minimum_padding_length);
int ComputeRSAAuthInfo(const char *in_filename, const char *private_key_filename, const char *passcode, int passcode_length, const char *auth_filename);

#pragma endregion

#endif