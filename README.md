# CryptographyProjects :closed_lock_with_key:

## Included Projects :open_file_folder:

### `C`

| Name            | Identification Code | Type              | Status                                                             | Description                                                                                                                             |
|-----------------|---------------------|-------------------|--------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| ASN.1 to BER    | `A2B`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Encoding of *ASN.1* structure in *BER* format                                                                                           |
| AES in ECB Mode | `AiE`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Implementation of *AES* in *ECB* mode                                                                                                   |
| AES in GCM Mode | `AiG`               | Homework          | ![](https://img.shields.io/badge/-partially%20working-yellowgreen) | Implementation of *AES* in *GCM* mode, according to [*NIST*'s *SP 800-38D*](https://csrc.nist.gov/publications/detail/sp/800-38d/final) |
| RSA             | `RSA`               | Laboratory        | ![](https://img.shields.io/badge/-working-brightgreen)             | Implementation of *RSA* on *2048* bits (key generation, encryption and decryption)                                                      |
| Final Homework  | `FH*`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Solves for miscellaneous cryptography problems (from working with encryption algorithms to MACs and signatures)                         |
| Utilities       | `UTL`               | Utility functions | ![](https://img.shields.io/badge/-working-brightgreen)             | Functions used in all other projects                                                                                                    |

### `Python 3`

| Name                                  | Identification Code | Type              | Status                                                             | Description                                                                                                                    |
|---------------------------------------|---------------------|-------------------|--------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| Bruteforce BC4                        | `bc4`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Bruteforce of a custom-made stream cipher                                                                                      |
| Crack Four-eye Principle              | `4ep`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Crack for a four-eye-based protocol                                                                                            |
| BMP Encryption with AES               | `bea`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Comparision of AES encryption mode over a BMP image                                                                            |
| Crack RSA with Factoring Database     | `fdb`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Crack for RSA encryption using a factoring database, [factordb](factordb.com)                                                  |
| Crack RSA with CRT                    | `crt`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Crack for RSA encryption using Chinese Remainder Theorem                                                                       |
| Utilities                             | `utl`               | Utility functions | ![](https://img.shields.io/badge/-working-brightgreen)             | Functions used in all other projects                                                                                           |

## Setup :wrench:

### `C`

1. **include** and **link** with *OpenSSL* by changing the configuration of *Visual Studio* project (the only one from the solution)
   - `include` folder added in **C / C++** - **General** - **Additional Include Directories**
   - `lib` folder added in **Linker** - **General** - **Additional Library Directories**
   - `libcrypto.lib` static library added in **Linker** - **Input** - **Additional Dependencies**
2. **change** project identification code in the marked `#define` in the `Main.c` source file

### `Python 3`

1. **install** required modules by running `python3 -m pip install -r requirements.txt`