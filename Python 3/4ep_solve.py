#!/usr/bin/env python3

# Import libraries
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from gmpy2 import mpz, iroot, to_binary, bit_length
from base64 import b64decode
from pwn import log

# Include handcrafted modules
from utl_converters import Converter

# Define constants
BLOB = Converter.hex_to_bytes("001893834df42280c7a3d695ed87d986a2dd87e5bf43c4b5dea50018172fff3690221206be2780bd99dc5a3c3a632d637595721d8e468c11326435bda16cd0e7fde4cc23")
ALICE_PUBLIC_KEY = "MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAzjQuC7VtSzbFjU4FbEYxMTWBQJTFh8zkXdiYhdDv/iH2k5XeZtm+6Zozz4MOrNRlyhcuqBjHyGmLp/DXz6VNbHXQOSSFpnPXOM+W96xGFp/EJ4qhxLagcY7uFMfXS/tHIfKq1yxBPnmHnrDNGve2taGhQaAyeXKkIn2X665aZgwzgVDiVjviBQFPqVT6U5HROOf6YzLhhPtCYaoiYLs/gCLhJJfGu9POJuRVVPElEA0eQW7bxmXPSXQRRFbq4NIoFoYOV6YS+qzv1sbTn2ZhI+pvT2HpdEvwx2S9L/j0PLdhCBQ7xUPX2Bg//d87JDYT1hOJImptwSVo0ZDaafvZ7QIBAw=="
BOB_PUBLIC_KEY = "MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAxXpbMNT1pMZaV/VwIDaOsWW7XKY7bksSPpJ0NpleJl9wBmXEVh1HnWYFd9fdBtlsQXsVxqxUNBYS6FdsHzgpG7Y0N7UZ4ISf3FKp12HmKxakfNM6Bj2rIYRPyFlCMZAvgmmKLNKgu8cm8cgKbSMemsgdOoO46Ft11Ywa801sVCCEpXJFT7PVNepTYMhQ+vU8Mr8r/YPxwrKLxdoXh8XJtj7FrmylHCWYvA91QIQpe4h4i1XdlBcDg01rnNplJVJoDOI7agXCT9XsA8zNGJ++iwoMT7Q+9xLOYVWw/rPjSBacpqH75DATpz7tMWw1bxPnXT1ShLTNnk41uB2qMZFfZQIBAw=="

# Get known algorithm parameters from blob
c1_length = Converter.bytes_to_int(BLOB[0:2])
c1 = BLOB[2:c1_length+2]
c2_length = Converter.bytes_to_int(BLOB[c1_length+2:c1_length+4])
c2 = BLOB[c1_length+4:-16]
encrypted_code = BLOB[-16:]

# Log algorithm parameters
log.info("C1, with length of {} bytes, is: {}".format(c1_length, Converter.bytes_to_hex(c1)))
log.info("C2, with length of {} bytes, is: {}".format(c2_length, Converter.bytes_to_hex(c2)))
log.info("Encrypted code is: {}".format(Converter.bytes_to_hex(encrypted_code)))

# Get RSA parameters (public exponent and modulus) from public keys
alice_public_key: RSA._RSAobj = RSA.importKey(b64decode(ALICE_PUBLIC_KEY))
alice_public_exponent = alice_public_key.e
alice_modulus = alice_public_key.n
bob_public_key: RSA._RSAobj = RSA.importKey(b64decode(BOB_PUBLIC_KEY))
bob_public_exponent = bob_public_key.e
bob_modulus = bob_public_key.n

# Log RSA parameters
log.info("Alice public key has public exponent {} and modulus {}".format(alice_public_exponent, alice_modulus))
log.info("Bob public key has public exponent {} and modulus {}".format(bob_public_exponent, bob_modulus))

# Get K1 and K2 in multi-precision form
res_k1 = iroot(mpz(Converter.bytes_to_int(c1)), alice_public_exponent)
res_k2 = iroot(mpz(Converter.bytes_to_int(c2)), bob_public_exponent)
if (res_k1[1] and res_k2[1]):

    # Convert results to bytes
    k1 = Converter.swap_endianness(to_binary(res_k1[0]))[:-2]
    k2 = Converter.swap_endianness(to_binary(res_k2[0]))[:-2]

    # Log
    log.success("Finded K1, with effective length of {} bits, is {}".format(bit_length(res_k1[0]), Converter.bytes_to_hex(k1)))
    log.success("Finded k2, with effective length of {} bits, is: {}".format(bit_length(res_k2[0]), Converter.bytes_to_hex(k2)))

else:

    # Force exitW
    log.failure("Failed to obtain K1 and K2")
    exit(0)

# Compute key used in AES
xor = bytes([_k1_char ^ _k2_char for _k1_char, _k2_char in zip(k1, k2)])
log.info("XOR between K1 and K2 is: {}".format(Converter.bytes_to_hex(xor)))
k = SHA256.new(xor).digest()
log.info("Key used for AES encryption is: {}".format(Converter.bytes_to_hex(k)))

# Decrypt secret code and remove padding
secret_code = AES.new(k, AES.MODE_ECB).decrypt(encrypted_code)[:-2]
log.success("Secret code is: {}".format(Converter.bytes_to_string(secret_code)))