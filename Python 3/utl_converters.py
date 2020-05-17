# Import libraries
from binascii import b2a_hex, a2b_hex
from struct import pack

# Class that contains converter from one type to another
class Converter:

    # Public method that transforms from bytes to int
    @staticmethod
    def bytes_to_int(x: bytes) -> int:

        return int.from_bytes(x, "big")

    # Public method that transforms from bytes to hex
    @staticmethod
    def bytes_to_hex(x: bytes) -> str:

        return "0x" + b2a_hex(x).decode("utf-8")

    # Public method that transforms from bytes to string
    @staticmethod
    def bytes_to_string(x: str) -> str:

        return x.decode("utf-8")

    # Public method that transforms from int to bytes
    @staticmethod
    def int_to_bytes(x: int) -> bytes:

        return pack(">I", x)
    
    # Public method that transforms from int to hex
    @staticmethod
    def int_to_hex(x: int) -> str:

        return hex(x)

    # Public method that transforms from hex to bytes
    @staticmethod
    def hex_to_bytes(x: str) -> bytes:

        return a2b_hex(x)

    # Public method that transforms from hex to int
    @staticmethod
    def hex_to_int(x: str) -> int:

        return int(x, 16)

    # Public method that transforms from string to bytes
    @staticmethod
    def string_to_bytes(x: str) -> bytes:

        return bytes(x, "utf-8")

    # Public method that swaps the endianness of a bytestring
    @staticmethod
    def swap_endianness(x: bytes) -> bytes:

        byte_array = bytearray(x)
        byte_array.reverse()

        return bytes(byte_array)