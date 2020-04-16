#pragma region IncludedHeaders

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "UTL_Input.h"

#pragma endregion

#pragma region FromKeyboard

char* stdin_read(int multiple_of, int *length){

	char buffer[MAX_STDIN_BUFFER];
	char *trimmed_buffer;
	int len, needed_size, rest, i, ret_val;

	// Read data
	ret_val = fgets(buffer, MAX_STDIN_BUFFER, stdin);
	len = strlen(buffer);
	buffer[len - 1] = '\0';

	// Allocate new buffer
	rest = len % multiple_of;
	if (rest == 0)
		needed_size = len;
	else 
		needed_size = len - rest + multiple_of;
	trimmed_buffer = (char *)malloc((needed_size + 1) * sizeof(char));
	if (trimmed_buffer == NULL)
		return NULL;

	// Copy text in the new buffer
	ret_val = strcpy(trimmed_buffer, buffer);
	if (rest != 0)
		for (i = len; i < needed_size + 1; i++)
			trimmed_buffer[i] = '\0';

	// Initialize length
	*length = needed_size;
	
	// Return
	return trimmed_buffer;

}

#pragma endregion