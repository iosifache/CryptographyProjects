#include <stdlib.h>
#include <stdio.h>
#include "UTL_Output.h"

#pragma region PrintingOnScreen

int print_hex(const void *data, int len){

    const unsigned char *ptr = data;

    // Print
    for (int i = 0; i < len; i++){
        printf("0x%02x ", *ptr);
        ptr += 1;
    }
    printf("\n");

    // Return
    return 0;

}

int print_hex_with_caption(const char* prefix_caption, const void* data, int len){
   
    // Print caption
    printf("%s", prefix_caption);

    // Print hex representation
    print_hex(data, len);

}

#pragma endregion

#pragma region FileDumping

int dump_to_file(const char *filename, const void *data, int len){

    FILE *file;
    int written_chars;

    // Open file
    file = fopen(filename, "wb");
    if (file == NULL)
        return -1;

    // Write to file
    written_chars = fwrite(data, 1, len, file);
    if (written_chars != len)
        return -1;

    // Close file
    fclose(file);

    // Return
    return 0;

}

#pragma endregion