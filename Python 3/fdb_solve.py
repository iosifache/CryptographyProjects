#!/usr/bin/env python3

# Import libraries
from gmpy2 import mpz, invert, powmod, to_binary
from pwn import log

# Import handcrafted modules
from utl_converters import Converter

# Define used constants, where P and Q are obtained with factordb.com
N = mpz(70736025239265239976315088690174594021646654881626421461009089480870633400973)
E = mpz(3)
C = mpz(28822365203577929536184039125870638440692316100772583657817939349051546473185)
P = mpz(238324208831434331628131715304428889871)
Q = mpz(296805874594538235115008173244022912163)

# Decrypt ciphertext
phi = mpz((P - 1) * (Q - 1))
d = invert(E, phi)
m = powmod(C, d, N)

# Print decrypted message
log.success("The decrypted message is: {}".format(Converter.bytes_to_string(to_binary(m))[::-1]))