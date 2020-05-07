#include "A2B_Seq_Homework.h"

#pragma region Sequence

ASN1_SEQUENCE(Homework) = {
		ASN1_SIMPLE(Homework, domain, ASN1_OBJECT),
		ASN1_SIMPLE(Homework, title, ASN1_UTF8STRING),
} ASN1_SEQUENCE_END(Homework)

#pragma endregion

#pragma region ASN1Functions

IMPLEMENT_ASN1_FUNCTIONS(Homework)

#pragma endregion