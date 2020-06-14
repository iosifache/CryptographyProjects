#!/usr/bin/env python3

# Import libraries
from gmpy2 import mpz, c_mod, invert, powmod, iroot, to_binary
from pwn import log

# Import handcrafted modules
from utl_converters import Converter

# Define used constants
E = mpz(3)
N1 = mpz(0xa8688af04ce3d0b93d04219391054740f10272ab96706cb98f852d8123e93853dfa4c4cf1fbb61cd632a2dad437e25003d545cded563e20581b6738a8080ac23)
N2 = mpz(0x70b2de4871351f2736f6f98eaed99ae6a68dd02954c536ebefdd553e7c7cf3003991bad6081061d04a6513e3d0db8be164f8e2e8e51deb1469832600957b7fe9)
N3 = mpz(0x586b8bccfa79b1a4e1332bccb897df08ad8e1867cee01ba003c74d861fd84ffe3cef3b652d45282bc18a6a11ca001f06500b78763932ae8044dfc21b6288fc91)
C1 = mpz(0x352cf1b545414223ce9ef6897258be836a282b5bf5d9050a7329bc0cabf8c700fbe2f4fef2a2d936eb08961406b1a2d6f288d18892e851ebe5afddb48723e89d)
C2 = mpz(0x1701b013a055ae8843ccfabceb1b29f79e676e2add6ca8256d893c754c1269820024ccd897d56f16d51f71023294d6d0ec30aaf1f9b07739bb9dfb7e3cb5ddb)
C3 = mpz(0x46f96866b9751c6492fe72f0169421e906915aab1065bc89d1712b086392f31585f4b409f645f968c918a1b16863bfadf95298f932ed30e52089a536146aae82)

# Compute ciphertext with Chinese Remainder Theorem
n = N1 * N2 * N3
n1 = N2 * N3
n2 = N1 * N3
n3 = N1 * N2
d1 = invert(n1, N1)
d2 = invert(n2, N2)
d3 = invert(n3, N3)
ciphertext = powmod(C1 * n1 * d1 + C2 * n2 * d2 + C3 * n3 * d3, 1, n)

# Decrypt the ciphertext using root, due to the small public exponent
(m, is_ok) = iroot(ciphertext, E)

# Print decrypted message
log.info("Truthfulness is: {}".format(is_ok))
log.success("The decrypted message is: {}".format(Converter.bytes_to_string(to_binary(m)[2:])[::-1]))