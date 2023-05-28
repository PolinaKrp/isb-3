import os
import logging
import pickle

from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes


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