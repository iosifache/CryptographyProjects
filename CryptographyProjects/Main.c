#pragma region IgnoredLibraries

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

#pragma endregion

#pragma region IncludedHeaders

#include "A2B_Main.h"
#include "AiE_Main.h"

#pragma endregion

#pragma region ChoosedProject

// Change this define with project's identifiers (out of UTL)
#define AiE

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

#pragma endregion

#pragma region Main

int main(int argc, char** argv){

	MAIN

}

#pragma endregion