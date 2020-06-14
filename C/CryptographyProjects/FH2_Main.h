#ifndef _FH2_MAIN_H

#define _FH2_MAIN_H

#pragma region Configuration

// Files
#define ADDITIONAL_FILES_FOLDER "W:\\Semester II\\Criptografie\\Homeworks\\CryptographyProjects\\C\\CryptographyProjects\\Additional Files\\2\\"
#define DOCUMENT_FILENAME ADDITIONAL_FILES_FOLDER "data.txt"
#define MAC_FILENAME ADDITIONAL_FILES_FOLDER "MAC.bin"
#define RSA_PRIVATE_KEY_FILENAME ADDITIONAL_FILES_FOLDER "private.key"
#define RSA_PUBLIC_KEY_FILENAME ADDITIONAL_FILES_FOLDER "public.key"

// Executed Operation: MAC Generation (define with 1) or MAC checking (define with 0)
#define IS_MAC_GENERATION 1

#pragma endregion

#pragma region MainFunction

int FH2_Main(int argc, char **argv);

#pragma endregion

#endif