#!/usr/bin/env python3

# Import handcrafter modules
from bc4_worker import BC4Worker
from utl_converters import Converter

# Defines constants used
CIPHERTEXT = "eda1e0bce19bde665dd62d3c9a1c3001dc523a07fab5c8c15ff2c0eab482e3a37d6389dfa0b458cae535b841f24d8a2ae7361b1d16abd2031367c3bdfa7be21250361cc5d23c3803ee95b4342794fb749645e2"
KNOWN_PLAINTEXT = "this will be"

# Bruteforce
ciphertext = Converter.hex_to_bytes(CIPHERTEXT)
known_plaintext = Converter.string_to_bytes(KNOWN_PLAINTEXT)
BC4Worker.brutefoce(ciphertext, known_plaintext)