#ifndef _FH2_INTERNALS_H

#define _FH2_INTERNALS_H

#pragma region IncludedHeaders

#include "UTL_Enumerations.h"

#pragma endregion

#pragma region Defines

#define PBKDF_HASH_ITERATION 10
#define SALT_SIZE 32

#define AES_256_GCM_KEY_SIZE 32
#define AES_256_GCM_IV_SIZE 12
#define AES_256_GCM_TAG_SIZE 16
#define RSA_3072_BLOCK_SIZE 384

#pragma endregion

#pragma region ExportedFunctions

int GenerateMAC(const char *document_filename, const char *private_key_filename, const char *mac_filename);
int CheckMAC(const char *document_filename, const char *public_key_filename, const char *mac_filename);

#pragma endregion

#endif