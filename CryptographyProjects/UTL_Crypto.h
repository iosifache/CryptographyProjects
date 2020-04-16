#ifndef _UTL_CRYPTO_H

#define _UTL_CRYPTO_H

#pragma region PaddingSchemes

void pkcs5_pad(char* buffer, int length, int multiple_of);
void pkcs5_unpad(char* buffer, int length, int multiple_of);

#pragma endregion

#endif