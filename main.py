import argparse
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import json
import os


def get_key(key):
    flag = False
    if os.path.exists('key.txt') is False:
        with open('key.txt', 'a'):
            os.utime('key.txt', None)

    with open('key.txt', 'r+') as file:
        if os.stat("key.txt").st_size == 0:
            file.write(key)
            flag = True
        else:
            key = file.readline()
    return str(key), flag


def generate_key_from_input(inp):
    salt = b'MyFixedSalt'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    inp = inp.encode('utf-8')
    key = base64.urlsafe_b64encode(kdf.derive(inp))
    return key


def encrypt_file(key):
    safe_key = generate_key_from_input(key)
    fernet = Fernet(safe_key)
    with open('passwords.json', 'rb') as file:
        original = file.read()

    encrypted = fernet.encrypt(original)
    with open('passwords.json', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    return encrypted


def decrypt_file(key):
    safe_key = generate_key_from_input(key)
    fernet = Fernet(safe_key)
    with open('passwords.json', 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open('passwords.json', 'wb') as decrypted_file:
        decrypted_file.write(decrypted)


def generate_password(simple_password, service_name):
    key = hashlib.sha256(simple_password.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_service_name = cipher.encrypt(pad(service_name.encode(), AES.block_size))
    generated_password = base64.b64encode(encrypted_service_name).decode()
    return generated_password


def save_password(service_name, comment, user_password, updating=False):
    generated_password = generate_password(user_password, service_name)
    key, flag = get_key(user_password)
    if flag is False and updating is False:
        decrypt_file(key)
    data = {"service_name": service_name, "password": generated_password, "comment": comment}
    with open("passwords.json", "a") as file:
        file.write(json.dumps(data) + '\n')
    if updating is False:
        encrypt_file(key)


def get_args(argument):
    split_values = argument.split()
    user = split_values[0]
    password = split_values[1]
    name = split_values[2]
    return user, password, name


def show_passwords():
    key, flag = get_key(None)
    if flag is False:
        decrypt_file(key)
    with open("passwords.json", "r") as file:
        for line in file:
            data = json.loads(line)
            print(data["service_name"])
    encrypt_file(key)


def show_password(service_name):
    key, flag = get_key(None)
    if flag is False:
        decrypt_file(key)
    with open("passwords.json", "r") as file:
        for line in file:
            data = json.loads(line)
            if data["service_name"] == service_name:
                print(f"Password: {data['password']}")
                print(f"Comment: {data['comment']}")
                break
        else:
            print(f"Password for {service_name} not found.")
    encrypt_file(key)


def update_password(service_name):
    key, flag = get_key(None)
    if flag is False:
        decrypt_file(key)
    with open("passwords.json", "r") as file:
        for line in file:
            data = json.loads(line)
            if data["service_name"] == service_name:
                password = data['password']
                comment = data['comment']
                delete_password(service_name, True)
                save_password(service_name, comment, password, True)
                break
        else:
            print(f"Password for {service_name} not found.")
    encrypt_file(key)


def delete_password(service_name, updating=False):
    key, flag = get_key(None)
    if flag is False and updating is False:
        decrypt_file(key)
    line_to_delete = -1
    with open("passwords.json", "r") as file:
        lines = file.readlines()
        for line in lines:
            data = json.loads(line)
            if data["service_name"] == service_name:
                line_to_delete = line
                break
        else:
            print(f"{service_name} not found.")

    with open("passwords.json", 'w') as file:
        for line in lines:
            if line is not line_to_delete:
                file.write(line)
    if updating is False:
        encrypt_file(key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Manager CLI")

    parser.add_argument("-newpass", metavar="user", help="User for the new password")

    parser.add_argument("-c", metavar="comment", help="Comment for the new password")

    parser.add_argument("-key", metavar="key", help="Key for the new password")

    parser.add_argument("-showpass", action="store_true", dest="showpass",
                        help="Show the names of passwords created and saved by the user")

    parser.add_argument("-sel", action="store", dest="sel",
                        help="Show the value of the password and its corresponding comment")

    parser.add_argument("-update", action="store", dest="update",
                        help="Update password value with new value")

    parser.add_argument("-del", action="store", dest="delete",
                        help="Remove password")

    args = parser.parse_args()

    if args.newpass:
        save_password(args.newpass, args.c, args.key)
    elif args.showpass:
        show_passwords()
    elif args.sel:
        show_password(args.sel)
    elif args.update:
        update_password(args.update)
    elif args.delete:
        delete_password(args.delete)
    else:
        print("Invalid command. Use -h for help.")
