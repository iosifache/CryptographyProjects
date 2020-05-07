#ifndef _A2B_SEQ_STUDENT

#define _A2B_SEQ_HOM_A2B_SEQ_STUDENTEWORK

#pragma region IncludedHeaders

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "A2B_Seq_Homework.h"
#include "A2B_Seq_FullName.h" 

#pragma endregion

#pragma region Structure

typedef struct {
	ASN1_INTEGER *age;
	ASN1_BOOLEAN *paid_schoolarship;
	FullName *full_name;
	Homework *homework;
} Student;

#pragma endregion

#pragma region ASN1Functions

DECLARE_ASN1_FUNCTIONS(Student);

#pragma endregion

#endif