#ifndef _UTL_CRYPTO_H

#define _UTL_CRYPTO_H

#pragma region IncludedHeaders

#include "UTL_Enumerations.h"
#include "UTL_Types.h"

#pragma endregion

#pragma region Configuration

#define AES_256_CBC_IV_LENGTH 32
#define AES_256_CBC_KEY_LENGTH 32

#pragma endregion

#pragma region EVPOperations

int ProcessFileWithAES256CBC(const char *input_filename, const char *ciphertext_filename, int are_parameters_readed, const char *key_filename, enum OperationType operation);

#pragma endregion

#pragma region PaddingSchemes

void pkcs1_pad(uchar *buffer, size message_length, size desired_length);
int pkcs1_unpad(uchar *buffer, size buffer_length);
void pkcs7_pad(uchar *buffer, size length, size multiple_of);
void pkcs7_unpad(uchar *buffer, size length, size multiple_of);

#pragma endregion

#endif