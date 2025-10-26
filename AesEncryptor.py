#!/usr/bin/env python3
"""
AesEncryptor.py by @808ale

Encrypt raw shellcode files and print them as byte arrays for pasting into c, powershell or csharp shellcode runners.

Usage examples:
    python AesEncryptor.py -c -buf payload_x64.bin
    python AesEncryptor.py -powershell -buf payload_x64.bin -buf86 payload_x86.bin
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from os import urandom
import argparse
from typing import Optional

# ****************************
# Encryptor Module
# ****************************
class Encryptor:
    """Utility class providing AES key/IV generation and AES-256-CBC encryption helper."""

    @staticmethod
    def generate_iv_aes() -> bytes:
        """
        Generate a random 16-byte AES IV.

        Returns:
            bytes: 16 random bytes suitable as an AES IV.
        """
        return urandom(16)

    @staticmethod
    def generate_key_aes() -> bytes:
        """
        Generate a random 32-byte AES key (AES-256).

        Returns:
            bytes: 32 random bytes suitable as an AES-256 key.
        """
        return urandom(32)

    @staticmethod
    def encrypt_bytes_to_bytes_aes(plain_bytes: bytes, aes_key: bytes, aes_iv: bytes) -> bytes:
        """
        Encrypt bytes with AES-256-CBC + PKCS7 padding.

        The return value is the IV concatenated with ciphertext: IV || ciphertext.
        This simplifies passing the IV along with the ciphertext to a decryptor.

        Args:
            plain_bytes (bytes): Plaintext bytes to encrypt.
            aes_key (bytes): 32-byte AES key.
            aes_iv (bytes): 16-byte AES initialization vector.

        Returns:
            bytes: Concatenation of IV and ciphertext (aes_iv + ciphertext).
        """
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_bytes) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return aes_iv + encrypted

# ****************************
# Printer Module
# ****************************
class Printer:
    """Helpers to format and print byte arrays for different languages (PowerShell, C#, C)."""

    #
    # POWERSHELL
    #
    @staticmethod
    def to_powershell_byte_array(byte_data: bytes) -> str:
        """
        Convert raw bytes to a comma-separated PowerShell hex byte list.

        Example output: "0xDE, 0xAD, 0xBE, 0xEF"
        """
        return ', '.join(f'0x{b:02X}' for b in byte_data)

    @staticmethod
    def print_powershell(aes_key: bytes, aes_iv: bytes, encrypted_buf: Optional[bytes], encrypted_buf86: Optional[bytes]) -> None:
        """
        Print AES key, AES IV, and encrypted buffers in PowerShell byte-array syntax.
        """
        def line(var_name: str, byte_array: bytes) -> str:
            return f"[Byte[]] ${var_name} = {Printer.to_powershell_byte_array(byte_array)}"

        print(line("AesKey", aes_key))
        print(line("AesIV", aes_iv))
        if encrypted_buf:
            print(line("buf", encrypted_buf))
        if encrypted_buf86:
            print(line("buf86", encrypted_buf86))

    #
    # CSHARP
    #
    @staticmethod
    def to_csharp_byte_array(byte_data: bytes) -> str:
        """
        Convert raw bytes to a comma-separated C# hex byte list.

        Example output: "0xDE, 0xAD, 0xBE, 0xEF"
        """
        return ', '.join(f'0x{b:02X}' for b in byte_data)

    @staticmethod
    def print_csharp(aes_key: bytes, aes_iv: bytes, encrypted_buf: Optional[bytes], encrypted_buf86: Optional[bytes]) -> None:
        """
        Print AES key, AES IV, and encrypted buffers in C# byte[] initializer syntax.
        """
        def line(var_name: str, byte_array: bytes) -> str:
            return f"public static byte[] {var_name} = new byte[] {{ {Printer.to_csharp_byte_array(byte_array)} }};"

        print(line("AesKey", aes_key))
        print(line("AesIv", aes_iv))
        if encrypted_buf:
            print(line("buf", encrypted_buf))
        if encrypted_buf86:
            print(line("buf86", encrypted_buf86))

    #
    # C
    #
    @staticmethod
    def to_c_byte_array(byte_data: bytes, line_len: int = 16) -> str:
        """
        Convert bytes into a formatted multi-line C string literal representation.

        Returns a string of the form:
            "\"\\xDE\\xAD...\"\\n    \"\\x...\""

        Args:
            byte_data (bytes): Bytes to format.
            line_len (int): Number of bytes per line.

        Returns:
            str: Formatted multi-line C string literal content.
        """
        lines = []
        for i in range(0, len(byte_data), line_len):
            chunk = byte_data[i:i + line_len]
            hexed = ''.join(f'\\x{b:02X}' for b in chunk)
            lines.append(f'"{hexed}"')
        return '\n    '.join(lines)

    @staticmethod
    def print_c(aes_key: bytes, aes_iv: bytes, encrypted_buf: Optional[bytes], encrypted_buf86: Optional[bytes]) -> None:
        """
        Print AES key, AES IV, and encrypted buffers in C-style unsigned char arrays.

        The output is formatted with a readable line length to make copy-paste into C code simple.
        """
        def line(var_name: str, byte_array: bytes) -> str:
            return f"unsigned char {var_name}[{len(byte_array)}] =\n    {Printer.to_c_byte_array(byte_array)};"

        print(line("AesKey", aes_key))
        print()
        print(line("AesIv", aes_iv))
        print()
        if encrypted_buf:
            print(line("buf", encrypted_buf))
            print()
        if encrypted_buf86:
            print(line("buf86", encrypted_buf86))

# ****************************
# Main Function
# ****************************
def main() -> None:
    """
    Command-line entrypoint.

    Supported arguments:
        -csharp       Output in C# format
        -powershell   Output in PowerShell format
        -c            Output in C format (default)
        -buf PATH     Path to x64 raw payload (binary)
        -buf86 PATH   Path to x86 raw payload (binary)
    """
    parser = argparse.ArgumentParser(description="Encrypt and output AES-encrypted shellcode in various formats.")
    parser.add_argument("-csharp", action="store_true", help="Print the output in C# format.")
    parser.add_argument("-powershell", action="store_true", help="Print the output in PowerShell format.")
    parser.add_argument("-c", action="store_true", help="Print the output in C format.")
    parser.add_argument("-buf", type=str, help="Path to .bin file containing raw x64 shellcode.")
    parser.add_argument("-buf86", type=str, help="Path to .bin file containing raw x86 shellcode.")
    # parser.add_argument("-o", type=str, help="(Optional) Output to file instead of stdout.") ← Add later if you want

    args = parser.parse_args()

    # Load buffers
    buf = buf86 = None
    if not args.buf and not args.buf86:
        parser.error("At least one of --buf or --buf86 must be specified.")
    if args.buf:
        with open(args.buf, 'rb') as f:
            buf = f.read()
    if args.buf86:
        with open(args.buf86, 'rb') as f:
            buf86 = f.read()

    # Generate AES key and IV
    aes_key = Encryptor.generate_key_aes()
    aes_iv = Encryptor.generate_iv_aes()

    # Encrypt both buffers if provided
    encrypted_buf = Encryptor.encrypt_bytes_to_bytes_aes(buf, aes_key, aes_iv) if buf else None
    encrypted_buf86 = Encryptor.encrypt_bytes_to_bytes_aes(buf86, aes_key, aes_iv) if buf86 else None

    # Dispatch format
    if args.csharp:
        Printer.print_csharp(aes_key, aes_iv, encrypted_buf, encrypted_buf86)
    elif args.powershell:
        Printer.print_powershell(aes_key, aes_iv, encrypted_buf, encrypted_buf86)
    elif args.c:
        Printer.print_c(aes_key, aes_iv, encrypted_buf, encrypted_buf86)
    else:
        # Default to C if no format specified
        Printer.print_c(aes_key, aes_iv, encrypted_buf, encrypted_buf86)

if __name__ == "__main__":
    main()

# TODO: automate payload generation (with flag) 
# TODO: next py script to create shellcode runners and populate with this script's output