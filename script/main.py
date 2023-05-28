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


def encrypt_data(text_file: str, secret_key_path: str, encrypted_symmetric_key_path: str,
                 encrypted_text_file_path: str):
    """
        Функция шифрует текст симметричным алгоритмом Camellia из файла по указанному пути, ключ симметричного алгоритма
        шифрования зашифрован ассиметричным алгоритмом RSA, поэтому предварительно ключ расшифровывается при помощи
        закрытого ключа RSA. Зашифрованный текст сохраняется в файл
        :param: text_file: Путь к файлу с текстом
        :param: secret_key_path: Путь к закрытому ключу ассиметричного шифра
        :param: encrypted_symmetric_key_path: Путь к зашифрованному ключу симметричного алгоритма Camellia
        :param: encrypted_text_file_path: Путь сохранения зашифрованного текста
        :return: None
    """
    try:
        with open(encrypted_symmetric_key_path, "rb") as file:
            encrypted_symmetric_key = file.read()
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {encrypted_symmetric_key_path} \nShutdown")
    try:
        with open(secret_key_path, 'rb') as pem_in:
            private_bytes = pem_in.read()
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {secret_key_path} \nShutdown")
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    try:
        with open(text_file, "r", encoding='UTF-8') as file:
            data = file.read()
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {text_file} \nShutdown")
    pad = padding2.ANSIX923(32).padder()
    text = bytes(data, 'UTF-8')
    padded_text = pad.update(text) + pad.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(decrypted_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)
    encrypted_data = {"encrypted_text": c_text, "iv": iv}
    try:
        with open(encrypted_text_file_path, "wb") as file:
            pickle.dump(encrypted_data, file)
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {encrypted_text_file_path} \nShutdown")


def decrypt_data(encrypted_text_file_path: str, secret_key_path: str, encrypted_symmetric_key_path: str,
                 decrypted_text_file_path: str):
    """
           Функция расшифровывает текст из указанного файла, предварительно расшифровывает ключ симметричного алгоритма,
           который был зашифрован ассиметричным алгоритмом RSA при помощи закрытого ключа
           :param: encrypted_text_file_path: Путь к зашифрованному тексту
           :param: secret_key_path: Путь к закрытому ключу ассиметричного шифра
           :param: encrypted_symmetric_key_path: Путь к зашифрованному ключу симметричного алгоритма шифрования
           :param: decrypted_text_file_path: Путь к расшифрованному тексту
           :return: None
    """
    try:
        with open(encrypted_symmetric_key_path, "rb") as file:
            encrypted_symmetric_key = file.read()
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {encrypted_symmetric_key_path} \nShutdown")
        exit()
    try:
        with open(secret_key_path, 'rb') as pem_in:
            private_bytes = pem_in.read()
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {secret_key_path} \nShutdown")
        exit()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    try:
        with open(encrypted_text_file_path, 'rb') as file:
            encrypted_text = pickle.load(file)
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {encrypted_text_file_path} \nShutdown")
    text = encrypted_text['encrypted_text']
    iv = encrypted_text['iv']
    cipher = Cipher(algorithms.Camellia(decrypted_symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(8).unpadder()
    unpadded_dc_data = unpadder.update(decrypted_text)
    final_text = unpadded_dc_data.decode('UTF-8')
    try:
        with open(decrypted_text_file_path, 'w', encoding='UTF-8') as file:
            file.write(final_text)
    except FileNotFoundError:
        logging.error(
            f"File oppening error: {decrypted_text_file_path} \nShutdown")

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