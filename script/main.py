import os
import json
import argparse
import pickle
import logging

from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from encrypt import encrypt_data
from decrypt import decrypt_data


SETTINGS = {
    'initial_file': "initial_file.txt",  
    'encrypted_file': 'encrypted_file.txt',  
    'decrypted_file': 'decrypted_file.txt',  
    'symmetric_key': 'symmetric_key.txt',  
    'public_key': 'public_key.pem',  
    'secret_key': 'secret_key.pem',  
}


def input_len_key(k_len: int):
    """
        Функция возвращает длину ключа для алгоритма Camellia
    """
    print("Choose key length:\n"
          "1: 128\n"
          "2: 192\n"
          "3: 256\n"
          "Make a decision. ")
    k_len = input()
    if int(k_len) == 1:
        return int(128)
    if int(k_len) == 2:
        return int(192)
    if int(k_len) == 3:
        return int(256)


def generate_key(encrypted_symmetric_key: str, public_key_path: str, secret_key_path: str, len_key: int) -> None:
    """
        Функция генерирует ключ симметричного алгоритма Camellia, публичный и закрытый ключи ассиметричного алгоритма
        RSA
        :param: symmetric_key_path: Путь к зашифрованному симметричному ключу
        :param: public_key_path: Путь к открытому ключу ассиметричного алгоритма
        :param: secret_key_path: Путь к закрытому ключу ассимтеричного алгоритма
        :return: key: длина ключа
    """
    symmetrical_key = algorithms.Camellia(os.urandom(int(len_key / 8)))
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    try:
        with open(public_key_path, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {public_key_path} \nShutdown")
    try:
        with open(secret_key_path, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {secret_key_path} \nShutdown")
    encrypt_symmetrical_key = public_key.encrypt(symmetrical_key.key,
                                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(),
                                                              label=None))
    try:
        with open(encrypted_symmetric_key, 'wb') as summetric_out:
            summetric_out.write(encrypt_symmetrical_key)
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {encrypted_symmetric_key} \nShutdown")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='main.py')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
    args = parser.parse_args()
    if args.generation:
        try:
            with open('settings.json') as json_file:
                json_data = json.load(json_file)
        except FileNotFoundError:
            logging.error(
                f"File oppening error: {json_data} \nShutdown")
        key_length = generate_key(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'])
        print('Key length: ' + str(key_length))
    if args.encryption:
        try:
            with open('settings.json') as json_file:
                json_data = json.load(json_file)
        except FileNotFoundError:
            logging.error(
                f"File oppening error: {json_data} \nShutdown")
        encrypt_data(json_data['initial_file'], json_data['secret_key'], json_data['symmetric_key'],
                    json_data['encrypted_file'])
        print('Encryption successful.\n')
    if args.decryption:
        try:
            with open('settings.json') as json_file:
                json_data = json.load(json_file)
        except FileNotFoundError:
            logging.error(
                f"File oppening error: {json_data} \nShutdown")
        decrypt_data(json_data['encrypted_file'], json_data['secret_key'], json_data['symmetric_key'],
                    json_data['decrypted_file'])
        print('Decryption successful.')