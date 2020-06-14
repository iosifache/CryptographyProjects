#!/usr/bin/env python3

# Import libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pwn import log

# Import handcrafted modules
from utl_converters import Converter

# Define used constants
PATH_TO_IMAGES = "Additional Files/amc/"
USED_MODES = [(AES.MODE_ECB, "ecb"), (AES.MODE_CBC, "cbc")]
BMP_EXTENSION = ".bmp"

# Get a random key and IV
iv = get_random_bytes(16)
key = get_random_bytes(16)
log.info("IV is: {}".format(Converter.bytes_to_hex(iv)))
log.info("Key is: {}".format(Converter.bytes_to_hex(key)))

# Read file to encrypt
file = open(PATH_TO_IMAGES + "original.bmp", "rb")
content = file.read()
file.close()

# Get headers (14 bytes for BMP and 40 bytes for DIB) and remove them from content
headers = content[0:54]
content = content[54:]

# Add PKCS#5 padding
padding_length = AES.block_size - len(content) % AES.block_size
content += padding_length * bytes([padding_length])

# Encrypt with AES-128, with a specific mode
for pair in USED_MODES:

    # Encrypt
    mode = pair[0]
    if (mode == AES.MODE_ECB):
        cipher = AES.new(key, mode)
    else:
        cipher = AES.new(key, mode, IV = iv)
    ciphertext = cipher.encrypt(content)

    # Output encrypted image
    name = pair[1]
    output_image = open(PATH_TO_IMAGES + name + BMP_EXTENSION, "wb")
    output_image.write(headers)
    output_image.write(ciphertext)
    output_image.close()

    # Log
    log.success("Success on generating encrypted image for {} mode".format(name.upper()))