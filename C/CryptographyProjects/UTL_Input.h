#ifndef _UTL_INPUT_H

#define _UTL_INPUT_H

#pragma region IncludedHeaders

#include "UTL_Configuration.h"
#include "UTL_Types.h"

#pragma endregion

#pragma region FromKeyboard

char *read_from_stdin(const char *caption, size *length);
char *block_read_from_stdin(const char *caption, int multiple_of, size *length);

#pragma endregion

#pragma region FromFile

char *read_file_content(const char *filename, size *size);

#pragma endregion

#endif