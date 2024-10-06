hexa_to_bin = {
                '0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100',
                '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001',
                'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'
               }

def bin_to_hexa(binary_str):
    hex_value = hex(int(binary_str, 2))[2:]
    return hex_value

def Encrypt(key, plaintext):
    # Key and message should be 8 bits (1 byte)
    if len(key) != 1 or len(plaintext) != 1:
        print("Error: Both key and plaintext must be 8 bits (1 byte).")
        return

    # Convert key and plaintext to binary
    bin_key = bin(int.from_bytes(key.encode(), 'big'))[2:].zfill(8)
    bin_plaintext = bin(int.from_bytes(plaintext.encode(), 'big'))[2:].zfill(8)
    
    print(f"Key in binary: {bin_key}")
    print(f"Plaintext in binary: {bin_plaintext}")

    # Basic XOR operation for encryption (simplified)
    cipher = ''.join(['1' if bin_key[i] != bin_plaintext[i] else '0' for i in range(8)])
    
    print(f"Cipher (binary): {cipher}")
    cipher_hex = bin_to_hexa(cipher)
    print(f"Cipher (hex): {cipher_hex}")

def Decrypt(key, cipher_hex):
    # Convert hex cipher to binary
    bin_cipher = bin(int(cipher_hex, 16))[2:].zfill(8)
    
    # Convert key to binary
    bin_key = bin(int.from_bytes(key.encode(), 'big'))[2:].zfill(8)
    
    print(f"Key in binary: {bin_key}")
    print(f"Cipher (binary): {bin_cipher}")

    # XOR operation for decryption (reverse of encryption)
    decrypted_bin = ''.join(['1' if bin_key[i] != bin_cipher[i] else '0' for i in range(8)])

    # Convert binary result to ASCII character
    decrypted_char = chr(int(decrypted_bin, 2))
    print(f"Decrypted character: {decrypted_char}")

# Example Usage
key = input("Enter 1-byte key: ")
plaintext = input("Enter 1-byte plaintext: ")

# Encryption
Encrypt(key, plaintext)

# For demonstration, manually enter cipher from above or store it
cipher_hex = input("Enter cipher hex to decrypt: ")

# Decryption
Decrypt(key, cipher_hex)


