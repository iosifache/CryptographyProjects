# Import libraries
from pwn import log
from tqdm.auto import tqdm

# Import handcrafted modules
from utl_converters import Converter

# Constants used in the BC4 algorithm
CHUNK_LENGTH = 4
KEY_LENGTH = 8
MODULO = 3525886283
MAX_NUMBER_TO_REACH = MODULO

# Configuration
VERBOSE = True

# Class that models a BC4 worker
class BC4Worker:

	# Members
	_verbose: bool = None

	# Private method that generates the stream key for BC4
	@staticmethod
	def _generate_keys(key: bytes, number_of_generated_keys: int) -> bytes:

		# Split the key into two ints, left and right
		left = Converter.bytes_to_int(key[:(KEY_LENGTH // 2)])
		right = Converter.bytes_to_int(key[(KEY_LENGTH // 2):])

		# Log
		if VERBOSE:
			log.info("Keys will be generated for key {}, with left {} and right {}".format(Converter.bytes_to_hex(key), Converter.bytes_to_hex(key[:(KEY_LENGTH // 2)]), Converter.bytes_to_hex(key[(KEY_LENGTH // 2):])))

		# Generate keys
		keys = bytes()
		for i in range(0, number_of_generated_keys):

			# Generate next right and left parts
			left = (5 * left + 11) % MODULO
			right = (7 * right + 13) % MODULO

			# XOR parts
			new_key_part = Converter.int_to_bytes(left ^ right)
			keys += new_key_part

			# Log
			if VERBOSE:
				log.info("Sub-key generated in the #{} iteration is {} (meaning {} ^ {})".format(i, Converter.bytes_to_hex(new_key_part), Converter.int_to_hex(left), Converter.int_to_hex(right)))

		# Log
		if VERBOSE:
			log.info("Keys generated is: {}".format(Converter.bytes_to_hex(keys)))

		# Return
		return keys

	# Public method that encrypts a text with BC4
	@staticmethod
	def encrypt(plain_text: bytes, key: bytes) -> bytes:

		# Check key parameter length
		key_length = len(key)
		if (key_length != KEY_LENGTH):
			log.warning("Key does not have the correct length: {} != {}".format(KEY_LENGTH, key_length))
			exit()
		else:
			log.success("Key have the correct length: {} == {}".format(KEY_LENGTH, key_length))

		# Check plain text parameter length
		plain_length = len(plain_text)
		if (plain_length % CHUNK_LENGTH != 0):
			log.warning("Text to encrypt does not have the correct length: {} % {} != 0".format(plain_length, CHUNK_LENGTH))
			exit()
		else:
			log.success("Text to encrypt has the correct length: {} % {} == 0".format(plain_length, CHUNK_LENGTH))
			log.info("Text to encrypt is: {}".format(Converter.bytes_to_hex(plain_text)))

		# Get keys used for encryption
		keys = BC4Worker._generate_keys(key, plain_length // CHUNK_LENGTH)

		# Split text in chunks and encrypt
		encrypted_text: bytes = bytes()
		for i in range(0, plain_length, CHUNK_LENGTH):

			# Get parts that will be XORed
			plain_part = plain_text[i:i+CHUNK_LENGTH]
			key_part = keys[i:i+CHUNK_LENGTH]

			# Encrypt with XOR
			ciphertext_part = Converter.bytes_to_int(plain_part) ^ Converter.bytes_to_int(key_part)
			encrypted_text += Converter.int_to_bytes(ciphertext_part)

			# Log
			if VERBOSE:
				log.info("The #{} encryption is {} (meaning {} ^ {})".format(i // CHUNK_LENGTH, Converter.int_to_hex(ciphertext_part), Converter.bytes_to_hex(plain_part), Converter.bytes_to_hex(key_part)))

		# Log
		if VERBOSE:
			log.info("Ciphertext is: {}".format(Converter.bytes_to_hex(encrypted_text)))

		# Encode encrypted text and return
		return encrypted_text

	# Public method that bruteforces the BC4 encrypted text
	@staticmethod
	def brutefoce(ciphertext: bytes, known_plaintext: bytes):

		# get parts for bruteforce
		known_plaintext_length = len(known_plaintext)
		ciphertext_part = ciphertext[0:known_plaintext_length]

		# log parts
		if VERBOSE:
			log.info("Ciphertext used in bruteforce is: {}".format(Converter.bytes_to_hex(ciphertext_part)))
			log.info("Plaintext used in bruteforce is: {}".format(Converter.bytes_to_hex(known_plaintext)))

		# get the known XOR between R and L
		known_key_part = bytes()
		for i in range(0, known_plaintext_length, CHUNK_LENGTH):

			# Get parts that will be XORed
			ciphertext_subpart = ciphertext_part[i:i+CHUNK_LENGTH]
			known_plaintext_part = known_plaintext[i:i+CHUNK_LENGTH]

			# XOR
			new_key_part = Converter.int_to_bytes(Converter.bytes_to_int(ciphertext_subpart) ^ Converter.bytes_to_int(known_plaintext_part))
			known_key_part += new_key_part
		
			# Log
			if VERBOSE:
				log.info("New known part of key is: {} (meaning {} ^ {})".format(Converter.bytes_to_hex(new_key_part), Converter.bytes_to_hex(ciphertext_subpart), Converter.bytes_to_hex(known_plaintext_part)))

		# create progress bar
		progress_bar = tqdm(total = MODULO, ascii = True, position = 0, leave = True)

		# bruteforce left part
		chunk_to_be_compared_with = known_key_part[CHUNK_LENGTH:]
		for left in range(0, MAX_NUMBER_TO_REACH):

			# get L
			right = Converter.bytes_to_int(known_key_part[0:CHUNK_LENGTH]) ^ left

			# compute new keys and compare to the known ones
			keys = BC4Worker._generate_keys(b"".join([Converter.int_to_bytes(left), Converter.int_to_bytes(right)]), known_plaintext_length // CHUNK_LENGTH - 1)
			if (keys == chunk_to_be_compared_with):
				log.success("Finded L and R are: ({}, {})".format(left, right))
				break

			# update progress bar
			progress_bar.update(n = 1)