from codecs import BOM_BE
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import binascii
import hashlib
import sys

from publickeycrypto import keyComp

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

    # MALLORY INSERTION
    x_M = int(number.getPrime(PRIME_LEN))
    while x_M >= n:
        x_M = number.getPrime(PRIME_LEN)
    y_M = rsa_encrypt(x_M, PU)
    print("Mallory attacks by using Alices Public Key and new s value for RSA Encryption" + 
    " and sending the new ciphertext to Alice who she thinks is bob")
    # Alice: Generate x using y given by MALLORY instead of Bob
    x_A = rsa_decrypt(y_M, PR)
    # Alice & Bob: Generate key k with respective calculated x
    h_A = hashlib.sha256(int(x_A).to_bytes(sys.getsizeof(x_A), "big"))
    k_A = h_A.hexdigest()[:16]
    h_M = hashlib.sha256(int(x_M).to_bytes(sys.getsizeof(x_M), "big"))
    k_M = h_M.hexdigest()[:16]

    # Test if they created same key
    if(k_A == k_M):
        print("Mallory and Alice now have the same key and will begin encryption")
    
    msg_A = "Hello Bob"
    msg_M = "This isn't bob"
    cbc_iv = get_random_bytes(16)
    cipher_A_enc = AES.new(bytes(k_A, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    cipher_A_dec = AES.new(bytes(k_A, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    cipher_M_enc = AES.new(bytes(k_M, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    cipher_M_dec = AES.new(bytes(k_M, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    ciphertext_A = cipher_A_enc.encrypt(pad(msg_A.encode(), 16))
    plaintext_M = unpad(cipher_M_dec.decrypt(ciphertext_A), 16).decode()
    ciphertext_M = cipher_M_enc.encrypt(pad(msg_M.encode(), 16))
    plaintext_A = unpad(cipher_A_dec.decrypt(ciphertext_M), 16).decode()
    print("Message from Alice, intercepted by Mallory: " + plaintext_M)
    print("Message from Mallory, received by Alice: " + plaintext_A)

if __name__ == '__main__':
    main()

