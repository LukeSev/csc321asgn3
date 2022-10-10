from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import hashlib
import sys

PRIME_LEN = 2048 # Length of prime numbers to be used

def rsa_encrypt(M, PU):
    # M = Plaintext as int
    # PU = Public Key
    e = PU[0]
    n = PU[1]
    
    """ if(M < n): # necessary condition
        return (M**e) % n
    else:
        return 0 """

    return (M**e) % n

def rsa_decrypt(C, PR):
    # C = Ciphertext as int
    # PR = Private Key
    d = PR[0]
    n = PR[1]
    print(C)
    print(d)
    print(n)
    return (C**d) % n


def main():
    # First, select/generate large primes
    p = number.getPrime(PRIME_LEN)
    q = number.getPrime(PRIME_LEN)
    e = 65537

    # Initial calculations
    n = p * q
    phi_n = (p-1) * (q-1)

    # Calculate d
    d = 1 / (e % phi_n)

    # Create public (PU) and private (PR) keys
    PU = [e,n]
    PR = [d,n]

    # Create string, convert to int, then encrypt
    M = int("Hello".encode('utf-8').hex(), 16)
    C = rsa_encrypt(M, PU)

    # Decrypt message as int, then convert back to ascii string
    C_out = rsa_decrypt(C, PR)
    C_hex = hex(C_out)[2:] # Remove '0x' from hex string
    msg_out = bytes.fromhex(C_hex).decode('utf-8')
    
    print(msg_out)

if __name__ == '__main__':
    main()