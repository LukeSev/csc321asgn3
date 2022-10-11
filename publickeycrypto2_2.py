from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import sys

# Compute key X given primes p, g, and root x
def keyComp(p, g, x):
    return (g**x) % p

def main():
    # Set up initial parameters for DH-Exchange
    p = int("B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C69A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C013ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD7098488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708DF1FB2BC 2E4A4371".replace(" ",""), 16)
    g = int("A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28AD662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24855E6EEB 22B3B2E5".replace(" ", ""), 16)

    # Alice's & Bob's chosen private keys
    a = 11
    b = 12

    # Mallory modifies g (Attack 2)
    g = 1

    # Calculate public keys
    A = keyComp(p, g, a)
    B = keyComp(p, g, b)

    # # Mallory modifies A and B (ATTACK 1)
    # A = p
    # B = p
    print("\nAfter Mallory changed the generator g to 1, the keys A and B are now", A, "and", B)
    # Now generate secret keys using others' public key
    s_A = int(keyComp(p, B, a))
    hash_A = hashlib.sha256(s_A.to_bytes(sys.getsizeof(s_A), "big")) # convert secret key to bytes before SHA-256
    k_A = hash_A.hexdigest()[:16] # Truncate to 16 bytes
    s_B = int(keyComp(p, A, b))
    hash_B = hashlib.sha256(s_B.to_bytes(sys.getsizeof(s_B), "big")) # convert secret key to bytes before SHA-256
    k_B = hash_B.hexdigest()[:16] # Truncate to 16 bytes
    s_M = int(keyComp(p, A, 1))
    hash_M = hashlib.sha256(s_M.to_bytes(sys.getsizeof(s_M), "big")) # convert secret key to bytes before SHA-256
    k_M = hash_M.hexdigest()[:16] # Truncate to 16 bytes

    print("Then when the key is computed by both parties, the Mallory can create the same key:\n")
    print("Alice's Key:", k_A, "Bob's Key:", k_B, "Mallory's Key:", k_M)
    # Test if same key is computed
    if k_A == k_B:
        print("\nAlice's and Bob's keys are EQUAL")
    else:
        print("\nAlice's and Bob's keys are NOT EQUAL")

    # Now to encrypt/decrypt some messages with out keys
    # First encrypt w/ Alice
    cbc_iv = get_random_bytes(16)
    cipher_A_enc = AES.new(bytes(k_A, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    m_A = "Hi Bob!"
    m_A_encrypted = cipher_A_enc.encrypt(pad(m_A.encode(), 16))
    cipher_B_enc = AES.new(bytes(k_B, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    m_B = "Hi Alice!"
    m_B_encrypted = cipher_B_enc.encrypt(pad(m_B.encode(), 16))

    # Now that everything has been encrypted, have Alice and Bob decrypt and print sent messages
    cipher_A_dec = AES.new(bytes(k_A, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    cipher_B_dec = AES.new(bytes(k_B, encoding='utf-8'), AES.MODE_CBC, cbc_iv)
    m_B_decrypted = unpad(cipher_A_dec.decrypt(m_B_encrypted), 16)
    m_A_decrypted = unpad(cipher_B_dec.decrypt(m_A_encrypted), 16)

    print("Bob's message to Alice: " + m_B_decrypted.decode())
    print("Alice's message to Bob: " + m_A_decrypted.decode() + "\n")


if __name__ == '__main__':
    main()