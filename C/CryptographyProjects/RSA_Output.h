#ifndef _RSA_ELEMENTS_H

#define _RSA_ELEMENTS_H

#pragma region IncludedHeaders

#include <openssl/rsa.h>

#pragma endregion

#pragma region WriteToFile

void RSA_write_key(RSA *key, const char *public_key_filename, const char *private_key_filename);

#pragma endregion

#endif