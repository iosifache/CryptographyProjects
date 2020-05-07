#include "A2B_Seq_Student.h"

#pragma region Sequence

ASN1_SEQUENCE(Student) = {
		ASN1_SIMPLE(Student, age, ASN1_INTEGER),
		ASN1_SIMPLE(Student, full_name, FullName),
		ASN1_SIMPLE(Student, paid_schoolarship, ASN1_BOOLEAN),
		ASN1_SIMPLE(Student, homework, Homework),
} ASN1_SEQUENCE_END(Student)

#pragma endregion

#pragma region ASN1Functions

IMPLEMENT_ASN1_FUNCTIONS(Student)

#pragma endregion