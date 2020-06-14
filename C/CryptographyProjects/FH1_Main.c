#pragma region IncludedHeaders

#include <openssl/rsa.h>
#include "FH1_Main.h"
#include "FH1_Internals.h"
#include "UTL_Logger.h"
#include "UTL_Enumerations.h"

#pragma endregion

#pragma region MainFunction

int FH1_Main(int argc, char **argv) {

	RSA *key = NULL;
	int ret_val, is_error = 1;

	// Encrypt file with AES256 in CBC mode
	ret_val = EncryptFileWithAES256CBC(HOMEWORK_DOCUMENT_FILENAME, AES_ENCRYPTED_HOMEWORK_DOCUMENT_FILENAME, KEY_FILENAME);
	GOTO_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "encrypting file with AES-256-CBC", FAIL_FH1_Main);

	// Generate RSA keys
	key = GenerateRSAKeyPair(RSA_KEY_SIZE, BIRTH_YEAR, PASSCODE, sizeof(PASSCODE) - 1, RSA_PRIVATE_KEY_FILENAME, RSA_PUBLIC_KEY_FILENAME);
	RETURN_LOGGER_CHECK_RET_VAL_NOT_EQUAL(key, NULL, "generating RSA key pair", 1);

	// Encrypt and decrypt with RSA, with previously generated files
	ret_val = EncryptFileWithRSA(AES_ENCRYPTED_HOMEWORK_DOCUMENT_FILENAME, RSA_AES_ENCRYPTED_HOMEWORK_DOCUMENT_FILENAME, key);
	GOTO_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "encrypting with RSA the (previously encrypted file, with AES-256-CBC) file", FAIL_FH1_Main);
	ret_val = DecryptFileWithRSA(RSA_AES_ENCRYPTED_HOMEWORK_DOCUMENT_FILENAME, DECRYPTED_AES_HOMEWORK_DOCUMENT_FILENAME, key);
	GOTO_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "decrypting with RSA the (previously encrypted file, with AES-256-CBC) file", FAIL_FH1_Main);
	
	// Mark function as successful
	is_error = 0;

	// Free memory
	FAIL_FH1_Main:
		RSA_free(key);

	// Return
	return is_error;

}

#pragma endregion