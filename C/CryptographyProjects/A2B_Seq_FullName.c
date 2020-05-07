#include "A2B_Seq_FullName.h"

#pragma region Sequence

ASN1_SEQUENCE(FullName) = {
		ASN1_SIMPLE(FullName, name, ASN1_PRINTABLESTRING),
		ASN1_SIMPLE(FullName, surname, ASN1_PRINTABLESTRING),
} ASN1_SEQUENCE_END(FullName)

#pragma endregion

#pragma region ASN1Functions

IMPLEMENT_ASN1_FUNCTIONS(FullName)

#pragma endregion