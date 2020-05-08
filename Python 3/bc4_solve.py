#!/usr/bin/env python3

# Import handcrafter modules
from bc4_worker import BC4Worker
from utl_converters import Converter
from pwn import log

# Defines constants used
CIPHERTEXT = "eda1e0bce19bde665dd62d3c9a1c3001dc523a07fab5c8c15ff2c0eab482e3a37d6389dfa0b458cae535b841f24d8a2ae7361b1d16abd2031367c3bdfa7be21250361cc5d23c3803ee95b4342794fb749645e2"
KNOWN_PLAINTEXT = "this will be"
KNOWN_L = 0x8b76a64d
SKIP_FIRST_ROUND = True

# Bruteforce to get key
ciphertext = Converter.hex_to_bytes(CIPHERTEXT)
known_plaintext = Converter.string_to_bytes(KNOWN_PLAINTEXT)
key = BC4Worker.brutefoce(ciphertext, known_plaintext, KNOWN_L)

# Add one byte to ciphertext to respect the length constrains
ciphertext += b'0'

# Decrypt with the help of encrypt algorithm
plaintext = BC4Worker.encrypt(ciphertext, key, SKIP_FIRST_ROUND)

# Print
log.success("Decrypted text is: {}".format(plaintext[:-1]))