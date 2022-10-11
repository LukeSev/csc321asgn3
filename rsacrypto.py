from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import binascii
import hashlib
import sys

PRIME_LEN = 2048 # Length of prime numbers to be used

def rsa_encrypt(x, PU):
    # M = Plaintext as int
    # PU = Public Key
    e = PU[0]
    n = PU[1]
    
    # if(M < n): # necessary condition
    #     return (M**e) % n
    # else:
    #     return 0

    return pow(x, e, n)

def rsa_decrypt(y, PR):
    # C = Ciphertext as int
    # PR = Private Key
    d = PR[0]
    n = PR[1]
    return pow(y, d, n)

def main():
    # First, select/generate large primes
    p = number.getPrime(PRIME_LEN)
    q = number.getPrime(PRIME_LEN)
    e = 65537

    # Initial calculations
    n = p * q
    phi_n = (p-1) * (q-1)

    # Calculate d
    # d = 1 / (e % phi_n)
    d = pow(e, -1, phi_n)

    # Alice: Create public (PU) and private (PR) keys
    PU = [e,n]
    PR = [d,n]

    # Bob: Create random number to be used to create key
    x_B = int(number.getPrime(PRIME_LEN))
    while x_B >= n:
        x_B = number.getPrime(PRIME_LEN)
    y = rsa_encrypt(x_B, PU)

    # Alice: Generate x using y given by Bob
    x_A = rsa_decrypt(y, PR)

    # Alice & Bob: Generate key k with respective calculated x
    h_A = hashlib.sha256(int(x_A).to_bytes(sys.getsizeof(x_A), "big"))
    k_A = h_A.hexdigest()[:16]
    h_B = hashlib.sha256(int(x_B).to_bytes(sys.getsizeof(x_B), "big"))
    k_B = h_B.hexdigest()[:16]

    if(x_A != x_B):
        print("\n\nX's ARE NOT EQUAL\n\n")
    if(k_A != k_B):
        print("\n\nKEYS ARE NOT EQUAL\n\n")
    test_msg = "Hello Bob"
    cbc_iv = get_random_bytes(16)
    cipher_A = AES.new(bytes(k_A, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    cipher_B = AES.new(bytes(k_B, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    ciphertext = cipher_A.encrypt(pad(test_msg.encode(), 16))
    plaintext = unpad(cipher_B.decrypt(ciphertext), 16).decode()
    print(plaintext)


if __name__ == '__main__':
    main()