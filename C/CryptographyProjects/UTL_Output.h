#ifndef _UTL_OUTPUT_H

#define _UTL_OUTPUT_H

#pragma region IncludedHeaders

#include "UTL_Types.h"

#pragma endregion

#pragma region PrintingOnScreen

int print_hex(const uchar *data, size length, const char *prefix_caption);

#pragma endregion

#pragma region FileDumping

int dump_to_file(const char *filename, const uchar *data, size length);
int check_identical_files(const char *first_filename, const char *second_filename);

#pragma endregion

#endif