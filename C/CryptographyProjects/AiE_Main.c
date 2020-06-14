#pragma region IncludedHeaders

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <conio.h>
#include "AiE_Main.h"
#include "UTL_Crypto.h"
#include "UTL_Input.h"
#include "UTL_Output.h"

#pragma endregion

#pragma region MainFunction

int AiE_Main(int argc, const char **argv){

	AES_KEY aes_enc_key, aes_dec_key;
	unsigned char user_key[AES_BLOCK_SIZE];
	unsigned char *data = NULL;
	unsigned char *encrypted_buffer = NULL;
	unsigned char *decrypted_buffer = NULL;
	int iteration_count, length, i, ret_val;

	// Read user data, add padding
	data = block_read_from_stdin("[+] Introduceti textul ce doriti a fi criptat: ", AES_BLOCK_SIZE , &length);
	pkcs7_pad(data, length, AES_BLOCK_SIZE);
	print_hex(data, length, "[+] Textul intrudus, cu padding-ul PKCS#7, este: ");

	// Allocate encrypted and decrypted buffers
	iteration_count = length / AES_BLOCK_SIZE;
	encrypted_buffer = (unsigned char*)malloc((length + 1) * sizeof(unsigned char));
	decrypted_buffer = (unsigned char*)malloc((length + 1) * sizeof(unsigned char));
	printf("[+] Numarul de iteratii ce vor fi facute este: %d\n", iteration_count);

	// Generate random key and set it for AES encryption
	RAND_bytes(user_key, AES_BLOCK_SIZE);
	ret_val = AES_set_encrypt_key(user_key, 8 * AES_BLOCK_SIZE, &aes_enc_key);
	if (ret_val){
		printf("[!] Eroare la asignarea cheii");
		exit(1);
	}
	print_hex(user_key, AES_BLOCK_SIZE, "[+] Cheia generata este: ");

	// Encrypt
	for (i = 0; i < iteration_count; i++)
		AES_encrypt(data + i * AES_BLOCK_SIZE, encrypted_buffer + i * AES_BLOCK_SIZE, &aes_enc_key);
	print_hex(encrypted_buffer, length, "[+] Textul criptat este: ");

	// Set key for AES decrypt
	ret_val = AES_set_decrypt_key(user_key, 8 * AES_BLOCK_SIZE, &aes_dec_key);
	if (ret_val){
		printf("[!] Eroare la asignarea cheii");
		exit(1);
	}

	// Decrypt
	for (i = 0; i < iteration_count; i++)
		AES_decrypt(encrypted_buffer + i * AES_BLOCK_SIZE, decrypted_buffer + i * AES_BLOCK_SIZE, &aes_dec_key);
	print_hex(decrypted_buffer, length, "[+] Textul decriptat este: ");

	// Unpad decrypted text
	pkcs7_unpad(decrypted_buffer, length, AES_BLOCK_SIZE);
	printf("[+] Textul decriptat, fara padding PKCS#7, este: %s\n", decrypted_buffer);

	// Free memory
	free(data);
	free(encrypted_buffer);
	free(decrypted_buffer);

	// Wait
	ret_val = _getch();

	// Return
	return 0;

}

#pragma endregion