#ifndef _A2B_SEQ_HOMEWORK

#define _A2B_SEQ_HOMEWORK

#pragma region IncludedHeaders

#include <openssl/asn1.h>
#include <openssl/asn1t.h>  

#pragma endregion

#pragma region Structure

typedef struct {
	ASN1_OBJECT *domain;
	ASN1_STRING *title;
} Homework;

#pragma endregion

#pragma region ASN1Functions

DECLARE_ASN1_FUNCTIONS(Homework);

#pragma endregion

#endif