#pragma region IncludedHeaders

#include <stdio.h>
#include <stdlib.h>
#include "FH4_Main.h"
#include "FH4_Internals.h"
#include "UTL_Input.h"
#include "UTL_Logger.h"

#pragma endregion

#pragma region MainFunction

int FH4_Main(int argc, char **argv){

	char *password = NULL, *plaintext = NULL;
	size password_length, plaintext_length;
	int ret_val;

	// Read password
	password = read_from_stdin("[+] Password is: ", &password_length);

	// Check if encryption is needed
	if (IS_ENCRYPTION){

		// Read plaintext
		plaintext = block_read_from_stdin("[+] Plaintext is: ", TRIPLE_DES_CBC_BLOCK_SIZE, &plaintext_length);

		// Encrypt
		ret_val = Encrypt(plaintext, plaintext_length, password, password_length, OUTPUT_FILENAME);
		GOTO_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "encrypting file with given password", FAIL_FH4_Main);

	}
	else{

		// Decrypt
		plaintext = Decrypt(OUTPUT_FILENAME, password, password_length, &plaintext_length);
		GOTO_LOGGER_CHECK_RET_VAL_NOT_EQUAL(plaintext, NULL, "decrypting (previously encrypted) file with given password", FAIL_FH4_Main);

		// Print plaintext
		printf("[+] Plaintext is: %s", plaintext);

	}

	// Free memory
	FAIL_FH4_Main:
		free(password);
		free(plaintext);

	// Return
	return 0;

}

#pragma endregion