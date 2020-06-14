#ifndef _FH5_MAIN_H

#define _FH5_MAIN_H

#pragma region Configuration

// Files
#define BASE_PATH "W:\\Semester II\\Criptografie\\Homeworks\\CryptographyProjects\\C\\CryptographyProjects\\Additional Files\\5\\"
#define INPUT_FILENAME BASE_PATH "input.txt"
#define KEY_FILENAME BASE_PATH "private.key"
#define SIGNATURE_FILENAME BASE_PATH "input.sigature"

// Password
#define PASSPHASE "passphase"

// Executed Rounds of Hashing
#define ROUNDS_NUMBER 10

// Executed Operation: Signing (define as 1) or Signature Verification (define as 0)
#define NEED_SIGN 1

#pragma endregion

#pragma region MainFunction

int FH5_Main(int argc, char **argv);

#pragma endregion

#endif