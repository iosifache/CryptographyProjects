#pragma region IncludedHeaders

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <conio.h>
#include "A2B_Main.h"
#include "A2B_Seq_Student.h"
#include "A2B_Configuration.h"
#include "UTL_Output.h"

#pragma endregion

#pragma region ImplementedASN1Types

IMPLEMENT_ASN1_FUNCTIONS(ASN1_BOOLEAN)

#pragma endregion

#pragma region MainFunction

int A2B_Main(int argc, char **argv){

    Student *student = NULL, *new_student = NULL;
    unsigned char *encoded = NULL;
    const unsigned char *const_encoded = NULL;
    int length, ret_val;

    // Create the student
    student = Student_new();

    // Create and init the full name
    student->full_name = FullName_new();
    student->full_name->name = ASN1_STRING_new();
    student->full_name->surname = ASN1_STRING_new();
    ASN1_STRING_set(student->full_name->name, FULLNAME_NAME, sizeof(FULLNAME_NAME));
    ASN1_STRING_set(student->full_name->surname, FULLNAME_SURNAME, sizeof(FULLNAME_SURNAME));

    // Create and init the homework
    student->homework = Homework_new();
    student->homework->title = ASN1_UTF8STRING_new();
    student->homework->domain = OBJ_txt2obj(HOMEWORK_DOMAIN, 1);
    ASN1_STRING_set(student->homework->title, HOMEWORK_TITLE, sizeof(HOMEWORK_TITLE));

    // Create and init the other details
    student->age = ASN1_INTEGER_new();
    student->paid_schoolarship = ASN1_BOOLEAN_new();
    ASN1_INTEGER_set(student->age, STUDENT_AGE);
    student->paid_schoolarship = STUDENT_PAID_SCHOOLARSHIP;

    // Encode the sequence
    length = i2d_Student(student, NULL);
    encoded = (unsigned char *)malloc(length * sizeof(unsigned char*));
    ret_val = i2d_Student(student, &encoded);

    // Print the encoding
    printf("[+] Encoding of length %d: ", ret_val);
    print_hex(encoded - ret_val, ret_val, NULL);
    printf("\n");

    // Decode the sequence
    const_encoded = encoded - ret_val;
    d2i_Student(&new_student, &const_encoded, length);

    // Verify the corectness of data
    if (new_student == NULL){
        printf("[!] Error while processing encoded data..\n");
        exit(0);
    }

    // Print an information of the decoded structure
    printf("[+] Name of the decoded student is: %s\n", ASN1_STRING_get0_data(new_student->full_name->name));

    // Free memory
    free(encoded);

    // Wait
    ret_val = _getch();

    // Return
    return 0;

}

#pragma endregion