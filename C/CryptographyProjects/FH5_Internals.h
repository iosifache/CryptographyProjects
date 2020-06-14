#ifndef _FH5_INTERNALS_H_

#define _FH5_INTERNALS_H_

#pragma region Configuration

#define MAX_MESSAGE_LENGTH 256
#define NOUNCE_LENGTH 16

#pragma endregion

#pragma region ExportedMethods

int CreateBlindSignature(const char *input_filename, const char *key_filename, const char *passphase, int passphase_length, int blindness_factor, const char *signature_filename);
int VerifyBlindSignature(const char *input_filename, const char *key_filename, const char *signature_filename);

#pragma endregion

#endif