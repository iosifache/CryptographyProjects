#ifndef _FH1_MAIN_H

#define _FH1_MAIN_H

#pragma region Configuration

// Files
#define ADDITIONAL_FILES_FOLDER "W:\\Semester II\\Criptografie\\Homeworks\\CryptographyProjects\\C\\CryptographyProjects\\Additional Files\\1\\"
#define RSA_PRIVATE_KEY_FILENAME ADDITIONAL_FILES_FOLDER "private.key"
#define RSA_PUBLIC_KEY_FILENAME ADDITIONAL_FILES_FOLDER "public.key"
#define HOMEWORK_DOCUMENT_FILENAME ADDITIONAL_FILES_FOLDER "Homework.docx"
#define AES_ENCRYPTED_HOMEWORK_DOCUMENT_FILENAME ADDITIONAL_FILES_FOLDER "Homework.aes"
#define RSA_AES_ENCRYPTED_HOMEWORK_DOCUMENT_FILENAME ADDITIONAL_FILES_FOLDER "Homework.aes.rsa"
#define DECRYPTED_AES_HOMEWORK_DOCUMENT_FILENAME ADDITIONAL_FILES_FOLDER "Homework.aes.dec"
#define KEY_FILENAME ADDITIONAL_FILES_FOLDER "aes.key"

// RSA Keys Configuration
#define RSA_KEY_SIZE 3072
#define BIRTH_YEAR 1998
#define PASSCODE "IOSI"

#pragma endregion

#pragma region MainFunction

int FH1_Main(int argc, char **argv);

#pragma endregion

#endif