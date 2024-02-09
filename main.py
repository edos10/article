import time
import binascii
from random import randbytes
from cha_cha_20 import run_tests, chacha20_encrypt
import random
import string
from arc4 import ARC4
from Crypto.Cipher import AES


def generate_random_string(length):
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    rand_string = ''.join(random.choice(letters) for i in range(length))
    return rand_string


def test_on_len(data_len: int):
    print(f"On length data: {data_len}")
    key = randbytes(16)
    iv = randbytes(16)
    plaintext = generate_random_string(data_len)
    message = plaintext.encode('utf-8')

    # encrypt the plaintext, using key and RC4 algorithm
    arc4 = ARC4(key)
    s = time.time()
    cipher = arc4.encrypt(message)
    e = time.time()
    print(f"Time for encrypt ARC4:", e - s)

    s = time.time()
    decrypted = arc4.decrypt(cipher)
    e = time.time()
    print(f"Time for decrypt ARC4:", e - s)
    # print('decrypted:', decrypted)

    s = time.time()
    encrypted_cha_message = chacha20_encrypt(message, key, iv=iv[:8])
    e = time.time()
    print(f"Time for encrypt ChaCha20: {e - s}")
    # print("Encrypted:", encrypted_cha_message)
    s = time.time()
    decrypted_message = chacha20_encrypt(encrypted_cha_message, key, iv=iv[:8])
    e = time.time()
    print(f"Time for decrypt ChaCha20: {e - s}")
    # print(decrypted_message)

    encryptor = AES.new(key, AES.MODE_CBC, iv)
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    s = time.time()
    encrypted_aes_message = encryptor.encrypt(message)
    e = time.time()
    print(f"Time for encrypt AES: {e - s}")

    s = time.time()
    decrypted_aes_message = decryptor.decrypt(encrypted_aes_message)
    e = time.time()
    print(f"Time for decrypt AES: {e - s}")
    print("-------------------")
    print()


def run_time_tests():
    test_on_len(400)
    test_on_len(2000)
    test_on_len(4000)
    test_on_len(10000)
    test_on_len(100000)
    test_on_len(800000)


if __name__ == "__main__":
    run_tests()
    run_time_tests()
