#pragma region IncludedHeaders

#include "FH3_Main.h"
#include "FH3_Internals.h"
#include "UTL_Output.h"
#include "UTL_Logger.h"

#pragma endregion

#pragma region MainFunction

int FH3_Main(int argc, char **argv){

	int ret_val;

	// Encrypt file with AES-256-CBC
	ret_val = ProcessFile(DOCUMENT_FILENAME, PARAMETERS_FILENAME, ENCRYPTED_FILENAME, OperationType_Encryption);
	RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "encrypting file with AES-256-CBC", 1);

	// Decrypt file with AES-256-CBC
	ret_val = ProcessFile(ENCRYPTED_FILENAME, PARAMETERS_FILENAME, DECRYPTED_FILENAME, OperationType_Decryption);
	RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "decrypting (previously encrypted) file with AES-256-CBC", 1);

	// Generating RSA key pair
	ret_val = GenerateRSAKeys(RSA2048_KEYS_BITLENGTH, KEYS_PUBLIC_EXPONENT, PASSCODE, sizeof(PASSCODE) - 1, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME);
	RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "generating RSA key pair", 1);

	// Dumping private key parameters
	ret_val = DumpRSAPrivateKey(PRIVATE_KEY_FILENAME, PASSCODE, sizeof(PASSCODE) - 1);
	RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "dumping RSA private key", 1);

	// Encrypting file
	ret_val = PaddedEncryptFileWithRSA(LOREM_FILENAME, PUBLIC_KEY_FILENAME, ENCRYPTED_LOREM_FILENAME, PADDING_VALUE, MIN_PADDING_LENGTH);
	RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "encrypting file with RSA public keys", 1);

	// Compute auth info for file
	ret_val = ComputeRSAAuthInfo(LOREM_FILENAME, PRIVATE_KEY_FILENAME, PASSCODE, sizeof(PASSCODE) - 1, AUTH_LOREM_FILENAME);
	RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "generating authentification info for file", 1);

	// Return
	return 0;

}

#pragma endregion