#ifndef _FH3_MAIN_H

#define _FH3_MAIN_H

#pragma region Configuration

#define BASE_PATH "W:\\Semester II\\Criptografie\\Homeworks\\CryptographyProjects\\C\\CryptographyProjects\\Additional Files\\3\\"

// First Requirement: Files
#define DOCUMENT_FILENAME BASE_PATH "document.txt"
#define PARAMETERS_FILENAME BASE_PATH "parameters.bin"
#define ENCRYPTED_FILENAME BASE_PATH "encrypted_document.aes"
#define DECRYPTED_FILENAME BASE_PATH "decrypted_document.txt"

// Second Requirement: Files
#define PRIVATE_KEY_FILENAME BASE_PATH "rsakey.prv"
#define PUBLIC_KEY_FILENAME BASE_PATH "rsakey.pub"

// Second Requirement: RSA Keys Configuration
#define RSA2048_KEYS_BITLENGTH 2048
#define KEYS_PUBLIC_EXPONENT 37
#define PASSCODE "passcode"

// Forth Requirement: Files
#define LOREM_FILENAME BASE_PATH "lorem.txt"
#define ENCRYPTED_LOREM_FILENAME BASE_PATH "encrypted_lorem.rsa"

// Fifth Requirement: Files
#define AUTH_LOREM_FILENAME BASE_PATH "lorem.auth"

// Fifth Requirement: Padding Configuration
#define PADDING_VALUE 0x1c
#define MIN_PADDING_LENGTH 10

#pragma endregion

#pragma region MainFunction

int FH5_Main(int argc, char **argv);

#pragma endregion

#endif