#pragma region IgnoredLibraries

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

#pragma endregion

#pragma region ChoosedProject

// Change this define with project's identifiers (out of UTL)
#define FH1

#ifdef NUL

	#define MAIN ;

#endif


#ifdef A2B

	#include "A2B_Main.h"

	#define MAIN A2B_Main(argc, argv);

#endif

#ifdef AiE

	#include "AiE_Main.h"

	#define MAIN AiE_Main(argc, argv);

#endif

#ifdef AiG

	#include "AiG_Main.h"

	#define MAIN AiG_Main(argc, argv);

#endif

#ifdef RSA

#include "RSA_Main.h"

#define MAIN RSA_Main(argc, argv);

#endif

#ifdef FH1

#include "FH1_Main.h"

#define MAIN FH1_Main(argc, argv);

#endif

#ifdef FH2

#include "FH2_Main.h"

#define MAIN FH2_Main(argc, argv);

#endif

#ifdef FH3

#include "FH3_Main.h"

#define MAIN FH3_Main(argc, argv);

#endif

#ifdef FH4

#include "FH4_Main.h"

#define MAIN FH4_Main(argc, argv);

#endif

#ifdef FH5

#include "FH5_Main.h"

#define MAIN FH5_Main(argc, argv);

#endif

#pragma endregion

#pragma region Main

int main(int argc, char **argv){

	MAIN

}

#pragma endregion