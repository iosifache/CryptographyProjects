#ifndef _FH4_MAIN_H

#define _FH4_MAIN_H

#pragma region Configuration

// Files
#define BASE_PATH "W:\\Semester II\\Criptografie\\Homeworks\\CryptographyProjects\\C\\CryptographyProjects\\Additional Files\\4\\"
#define OUTPUT_FILENAME BASE_PATH "ciphertext.3des"

// Executed Operation: Encryption (define with 1) or Decryption (define with 0)
#define IS_ENCRYPTION 1

#pragma endregion

#pragma region MainFunction

int FH4_Main(int argc, char **argv);

#pragma endregion

#endif