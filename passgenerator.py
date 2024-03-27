import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import random
import string


def generate_password(simple_password, service_name):
    key = hashlib.sha256(simple_password.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_service_name = cipher.encrypt(pad(service_name.encode(), AES.block_size))
    generated_password = base64.b64encode(encrypted_service_name).decode()
    return generated_password


if __name__ == "__main__":
    passwords = []
    for i in range(10000):
        n = random.randint(1, 100)
        res = ''.join(random.choices(string.ascii_letters, k=n))
        passwords.append(generate_password("0000", res))
    with open("test.txt", "w") as file:
        for password in passwords:
            file.write(password + "\n")
