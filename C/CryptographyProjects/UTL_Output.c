#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "UTL_Input.h"
#include "UTL_Output.h"

#pragma region PrintingOnScreen

int print_hex(const uchar *data, size length, const char *prefix_caption){

    uchar *current = NULL;

    // Print caption
    if (prefix_caption != NULL)
        printf("%s", prefix_caption);

    // Print hex
    current = data;
    for (int i = 0; i < length; i++){
        printf("0x%02x ", *current);
        current++;
    }
    printf("\n");

    // Return
    return 0;

}

#pragma endregion

#pragma region FileDumping

int dump_to_file(const char *filename, const uchar *data, size length){

    FILE *file = NULL;
    int written_chars;

    // Open file
    file = fopen(filename, "wb");
    if (file == NULL)
        return -1;

    // Write to file
    written_chars = fwrite(data, 1, length, file);
    if (written_chars != length)
        return -1;

    // Close file
    fclose(file);

    // Return
    return 0;

}

int check_identical_files(const char *first_filename, const char *second_filename){

    uchar *first_content = NULL, *second_content = NULL;
    size first_content_length, second_content_length;
    int is_identical = 0;

    // Read first file content
    first_content = read_file_content(first_filename, &first_content_length);
    if (first_content == NULL)
        return 0;

    // Read first file content
    second_content = read_file_content(second_filename, &second_content_length);
    if (second_content == NULL)
        goto FAIL_check_identical_files_1;

    // Verify that the contents has the same size
    if (first_content_length == second_content_length && memcmp(first_content, second_content, first_content_length) == 0)
        is_identical = 1;

    // Free memory
    FAIL_check_identical_files_2:
        free(second_content);
    FAIL_check_identical_files_1:
        free(first_content);

    // Return
    return is_identical;

}

#pragma endregion