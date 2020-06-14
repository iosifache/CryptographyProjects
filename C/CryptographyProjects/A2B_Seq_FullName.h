#ifndef _A2B_SEQ_FULLNAME_H

#define _A2B_SEQ_FULLNAME_H

#pragma region IncludedHeaders

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#pragma endregion

#pragma region Structure

typedef struct {
	ASN1_PRINTABLESTRING *name;
	ASN1_PRINTABLESTRING *surname;
} FullName;

#pragma endregion

#pragma region ASN1Functions

DECLARE_ASN1_FUNCTIONS(FullName);

#pragma endregion

#endif