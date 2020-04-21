#pragma region IncludedLibraries

#include <string.h>
#include "UTL_Crypto.h"

#pragma endregion

#pragma region PaddingSchemes

void pkcs7_pad(char *buffer, int length, int multiple_of){

	int actual_strlen, pad_value, i;

	// Verify parameters
	if (length % multiple_of != 0)
		return -1;

	// Get value for padding
	actual_strlen = strlen(buffer);
	pad_value = multiple_of - actual_strlen % multiple_of;

	// Fill with the value
	if (pad_value != 0)
		for (i = actual_strlen; i < length; i++)
			buffer[i] = pad_value;

}

void pkcs7_unpad(char* buffer, int length, int multiple_of){

	int flag = 1;
	int possible_padding_value, i;

	// Verify parameters
	if (length % multiple_of != 0)
		return -1;

	// Get padding value
	possible_padding_value = buffer[length - 1];

	// Verify if text is padded
	for (i = length - 2; i > length - possible_padding_value; i--)
		if (buffer[i] != possible_padding_value) {
			flag = 0;
			break;
		}

	// Check if padding must be removed
	if (flag == 1)
		for (i = length - 1; i > length - possible_padding_value - 1; i--)
			buffer[i] = '\0';

	// Return
	return 0;

}

#pragma endregion