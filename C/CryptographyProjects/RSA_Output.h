#ifndef _RSA_OUTPUT_H

#define _RSA_OUTPUT_H

#pragma region IncludedHeaders

#include <openssl/rsa.h>

#pragma endregion

#pragma region DumpToScreen

void RSA_dump_private_key(const RSA *key);

#pragma endregion

#pragma region WriteToFile

void RSA_write_keys(RSA *key, const char *public_key_filename, const char *private_key_filename);
void RSA_write_encrypted_keys(RSA *key, const char *passcode, int passcode_length, const char* public_key_filename, const char* private_key_filename);

#pragma endregion

#endif