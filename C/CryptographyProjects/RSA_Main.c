#include "RSA_Main.h"

#pragma region IncludedHeaders

#include "RSA_Elements.h"
#include "UTL_Output.h"

#pragma endregion

#pragma region Configuration

#define PUBLIC_EXPONENT 3
#define PLAINTEXT "RSA is one of the first public-key cryptosystems"
#define PLAINTEXT_LENGTH 49

#pragma endregion

#pragma region MainFunction

int RSA_Main(int argc, char** argv){

	RSA *key;
	uchar *ciphertext, *decrypted;
	uchar plaintext[] = PLAINTEXT;
	int ciphertext_length;

	// Generate keypair
	key = RSA_generate_manual_key(PUBLIC_EXPONENT);

	// Encrypt text
	ciphertext = RSA_encrypt(key, plaintext, PLAINTEXT_LENGTH, &ciphertext_length);
	print_hex_with_caption("[+] Encrypted text is: ", ciphertext, ciphertext_length);

	// Decrypt text
	decrypted = RSA_decrypt(key, ciphertext, ciphertext_length);
	print_hex_with_caption("[+] Decrypted text is: ", decrypted, PLAINTEXT_LENGTH);

	// Return
	return 0;

}

#pragma endregion