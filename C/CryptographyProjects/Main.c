#pragma region IgnoredLibraries

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")

#pragma endregion

#pragma region ChoosedProject

// Change this define with project's identifiers (out of UTL)
#define AiG

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

#pragma endregion

#pragma region Main

int main(int argc, char** argv){

	MAIN

}

#pragma endregion