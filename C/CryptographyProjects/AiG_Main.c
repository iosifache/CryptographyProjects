#pragma region IncludedHeaders

#include <openssl/rand.h>
#include <stdio.h>
#include "AiG_Main.h"
#include "AiG_Elements.h"
#include "UTL_Output.h"
#include "UTL_Math.h"

#pragma endregion

#pragma region Configuration

#define PLAINTEXT_LENGTH 32
#define AAD_LENGTH 16
#define WILL_FAIL 0

#pragma endregion

#pragma region MainFunction

int AiG_Main(int argc, const char **argv){

	uchar plaintext[PLAINTEXT_LENGTH] = "Lorem ipsum dolor sit amet eros.";
	uchar aad[AAD_LENGTH] = "Lorem ipsum sit.";
	uchar iv[IV_RECOMMENDED_LENGTH] = {0};
	uchar user_key[KEY_SIZE] = {0};
	uchar ciphertext[PLAINTEXT_LENGTH] = {0};
	uchar tag[MIN_TAG_LENGTH] = {0};
	uchar decrypted[PLAINTEXT_LENGTH] = {0};
	int ret_val;

	// Generate key and IV
	RAND_bytes(iv, IV_RECOMMENDED_LENGTH);
	RAND_bytes(user_key, KEY_SIZE);

	// Set key to context
	InitContext(user_key);

	// Print parameters
	print_hex_with_caption("[+] Textul in clar este: ", plaintext, PLAINTEXT_LENGTH);
	print_hex_with_caption("[+] Informatiile aditionale sunt: ", aad, AAD_LENGTH);
	print_hex_with_caption("[+] Cheia este: ", user_key, KEY_SIZE);
	print_hex_with_caption("[+] Vectorul de initializare este: ", iv, IV_RECOMMENDED_LENGTH);

	// Encrypt and print the result
	AuthEncryptWithGCM(plaintext, PLAINTEXT_LENGTH, aad, AAD_LENGTH, iv, MIN_TAG_LENGTH, ciphertext, tag);
	print_hex_with_caption("[+] Textul criptat este: ", ciphertext, PLAINTEXT_LENGTH);
	print_hex_with_caption("[+] Tag-ul de autentificare este: ", tag, MIN_TAG_LENGTH);

	// Check if the decryption need to fail (by changing the AAD)
	if (WILL_FAIL)
		aad[0] = 0;

	// Decrypt
	ret_val = AuthDecryptWithGCM(ciphertext, PLAINTEXT_LENGTH, aad, AAD_LENGTH, iv, tag, MIN_TAG_LENGTH, decrypted);
	if (ret_val)
		printf("[!] Decriptarea a esuat din cauza unor erori sau a esecului validarii tag-ului de autentificare");
	else
		print_hex_with_caption("[+] Textul decriptat este: ", decrypted, PLAINTEXT_LENGTH);

	// Delete the context
	FreeContext();

}

#pragma endregion