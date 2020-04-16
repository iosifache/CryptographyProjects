# CryptographyProjects :closed_lock_with_key:

## Included Projects :open_file_folder:

| Name            | Identification Code | Type              | Description                                   |
|-----------------|---------------------|-------------------|-----------------------------------------------|
| ASN.1 to BER    | `A2B`               | Homework          | Coding of *ASN.1* structure in *BER* format   | 
| AES in ECB Mode | `AiE`               | Homework          | Implementation of *AES* in *ECB* mode         |
| Utilities       | `UTL`               | Utility functions | Functions used in all other projects          |

## Setup :wrench:
1. **include** and **link** with *OpenSSL* by changing the configuration of *Visual Studio* project (the only one from the solution)
   - `include` folder added in **C / C++** - **General** - **Additional Include Directories**
   - `lib` folder added in **Linker** - **General** - **Additional Library Directories**
   - `libcrypto.lib` static library added in **Linker** - **Input** - **Additional Dependencies**
2. **change** project identification code in the marked `#define` in the `Main.c` source file