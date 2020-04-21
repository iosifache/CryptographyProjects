#ifndef _UTL_CRYPTO_H

#define _UTL_CRYPTO_H

#pragma region PaddingSchemes

void pkcs7_pad(char* buffer, int length, int multiple_of);
void pkcs7_unpad(char* buffer, int length, int multiple_of);

#pragma endregion

#endif