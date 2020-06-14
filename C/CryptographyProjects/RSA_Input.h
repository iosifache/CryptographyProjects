#ifndef _RSA_INPUT_H

#define _RSA_INPUT_H

#pragma region IncludedHeaders

#include <openssl/rsa.h>

#pragma endregion

#pragma region ReadFromFile

RSA *RSA_read_public_key(const char *public_key_filename);
RSA *RSA_read_private_key(const char *private_key_filename, const char *passcode, int passcode_length);

#pragma endregion

#endif