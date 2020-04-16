#ifndef _UTL_OUTPUT_H

#define _UTL_OUTPUT_H

#pragma region PrintingOnScreen

int print_hex(const void *data, int len);
int print_hex_with_caption(const char *prefix_caption, const void* data, int len);

#pragma endregion

#pragma region FileDumping

int dump_to_file(const char *filename, const void *data, int len);

#pragma endregion

#endif