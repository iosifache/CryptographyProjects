#pragma region IncludedHeaders

#include "FH2_Main.h"
#include "FH2_Internals.h"
#include "UTL_Logger.h"

#pragma endregion

#pragma region MainFunction

int FH2_Main(int argc, char **argv){

	int ret_val;

	// Generate or check MAC, depending on desired operation
	if (IS_MAC_GENERATION){
		ret_val = GenerateMAC(DOCUMENT_FILENAME, RSA_PRIVATE_KEY_FILENAME, MAC_FILENAME);
		RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "generating MAC for file", 1);

	}
	else{
		ret_val = CheckMAC(DOCUMENT_FILENAME, RSA_PUBLIC_KEY_FILENAME, MAC_FILENAME);
		RETURN_LOGGER_CHECK_RET_VAL_EQUAL(ret_val, 0, "checking MAC for file", 1);
	}

}

#pragma endregion