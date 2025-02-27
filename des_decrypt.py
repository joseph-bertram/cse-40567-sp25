from Crypto.Cipher import DES
from binascii import unhexlify

def binary_to_bytes(binary_str):
    """ Convert a binary string to bytes. """
    return int(binary_str, 2).to_bytes(len(binary_str) // 8, byteorder='big')

def des_decrypt(ciphertext_bin, key_bin):
    """ Perform DES decryption in ECB mode. """
    # Convert binary inputs to bytes
    ciphertext = binary_to_bytes(ciphertext_bin)
    key = binary_to_bytes(key_bin)
    
    # Initialize DES cipher in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext

if __name__ == "__main__":
    # Given binary ciphertext and key
    ciphertext_bin = "1100101011101101101000100110010101011111101101110011100001110011"
    key_bin = "0100110001001111010101100100010101000011010100110100111001000100"
    
    # Decrypt the message
    plaintext = des_decrypt(ciphertext_bin, key_bin)
    
    # Print the decrypted plaintext
    print("Decrypted plaintext:", plaintext.decode(errors='ignore'))

