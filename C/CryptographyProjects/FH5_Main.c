#pragma region IncludedHeaders

#include "FH5_Main.h"
#include "FH5_Internals.h"
#include "UTL_Logger.h"

#pragma endregion

#pragma region MainFunction

int FH5_Main(int argc, char **argv){

	int ret_val;

	// Check operation that will be executed
	if (NEED_SIGN) {
		ret_val = CreateBlindSignature(INPUT_FILENAME, KEY_FILENAME, PASSPHASE, sizeof(PASSPHASE), ROUNDS_NUMBER, SIGNATURE_FILENAME);
		RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "creating bling signature");
	}
	else{
		ret_val = VerifyBlindSignature(INPUT_FILENAME, KEY_FILENAME, SIGNATURE_FILENAME);
		RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "verifying valid bling signature");
	}

}

#pragma endregion