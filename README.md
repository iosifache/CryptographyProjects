# CryptographyProjects :closed_lock_with_key:

## Included Projects :open_file_folder:

### `C`

| Name            | Identification Code | Type              | Status                                                             | Description                                                                                                                             |
|-----------------|---------------------|-------------------|--------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| ASN.1 to BER    | `A2B`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Encoding of *ASN.1* structure in *BER* format                                                                                           |
| AES in ECB Mode | `AiE`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Implementation of *AES* in *ECB* mode                                                                                                   |
| AES in GCM Mode | `AiG`               | Homework          | ![](https://img.shields.io/badge/-partially%20working-yellowgreen) | Implementation of *AES* in *GCM* mode, according to [*NIST*'s *SP 800-38D*](https://csrc.nist.gov/publications/detail/sp/800-38d/final) |
| Utilities       | `UTL`               | Utility functions | ![](https://img.shields.io/badge/-working-brightgreen)             | Functions used in all other projects                                                                                                    |

### `Python 3`

| Name            | Identification Code | Type              | Status                                                             | Description                                                                                                                             |
|-----------------|---------------------|-------------------|--------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Bruteforce BC4  | `bc4`               | Homework          | ![](https://img.shields.io/badge/-working-brightgreen)             | Bruteforce of a custom-made stream cipher                                                                                               |
| Utilities       | `utl`               | Utility functions | ![](https://img.shields.io/badge/-working-brightgreen)             | Functions used in all other projects                                                                                                    |

## Setup :wrench:

### `C`

1. **include** and **link** with *OpenSSL* by changing the configuration of *Visual Studio* project (the only one from the solution)
   - `include` folder added in **C / C++** - **General** - **Additional Include Directories**
   - `lib` folder added in **Linker** - **General** - **Additional Library Directories**
   - `libcrypto.lib` static library added in **Linker** - **Input** - **Additional Dependencies**
2. **change** project identification code in the marked `#define` in the `Main.c` source file

### `Python 3`

1. **install** required modules by running `python3 -m pip install -r requirements.txt`