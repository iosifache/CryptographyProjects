#pragma region IncludedHeaders

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "UTL_Input.h"

#pragma endregion

#pragma region FromKeyboard

char *read_from_stdin(const char *caption, size *length){

	char buffer[MAX_STDIN_BUFFER];
	char *trimmed_buffer = NULL;
	size buffer_length;
	int ret_val;

	// Print caption
	if (caption != NULL)
		printf("%s", caption);

	// Read data
	ret_val = fgets(buffer, MAX_STDIN_BUFFER, stdin);
	buffer_length = strlen(buffer);
	buffer[buffer_length - 1] = '\0';

	// Allocate new buffer
	trimmed_buffer = (char*)malloc((buffer_length + 1) * sizeof(char));
	if (trimmed_buffer == NULL)
		return NULL;

	// Save results
	strcpy(trimmed_buffer, buffer);
	*length = buffer_length;

	// Return
	return trimmed_buffer;

}

char *block_read_from_stdin(const char *caption, int multiple_of, size *length){

	char buffer[MAX_STDIN_BUFFER];
	char *trimmed_buffer = NULL;
	size buffer_length, needed_length;
	int rest, i, ret_val;

	// Print caption
	if (caption != NULL)
		printf("%s", caption);

	// Read data
	ret_val = fgets(buffer, MAX_STDIN_BUFFER, stdin);
	buffer_length = strlen(buffer);
	buffer[buffer_length - 1] = '\0';

	// Allocate new buffer
	rest = buffer_length % multiple_of;
	if (rest == 0)
		needed_length = buffer_length;
	else 
		needed_length = buffer_length - rest + multiple_of;
	trimmed_buffer = (char *)malloc((needed_length + 1) * sizeof(char));
	if (trimmed_buffer == NULL)
		return NULL;

	// Copy text in the new buffer
	ret_val = strcpy(trimmed_buffer, buffer);
	if (rest != 0)
		for (i = buffer_length; i < needed_length + 1; i++)
			trimmed_buffer[i] = '\0';

	// Initialize length
	*length = needed_length;
	
	// Return
	return trimmed_buffer;

}

#pragma endregion

#pragma region FromFile

char *read_file_content(const char *filename, size *buffer_size){

	FILE *input;
	char *returned = NULL;
	size content_length;

	// Check parameters
	if (filename == NULL)
		return NULL;

	// Open file
	input = fopen(filename, "rb");
	if (input == NULL)
		return NULL;

	// Get file size
	fseek(input, 0, SEEK_END);
	content_length = ftell(input);
	fseek(input, 0, SEEK_SET);

	// Allocate new buffer
	returned = (char *)malloc(content_length * sizeof(char));
	if (returned == NULL){
		fclose(input);
		return NULL;
	}

	// Read file content
	fread(returned, content_length, 1, input);

	// Close file handle
	fclose(input);

	// Set buffer size
	*buffer_size = content_length;

	// Return
	return returned;

}

#pragma endregion