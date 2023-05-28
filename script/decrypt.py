import os
import logging
import pickle

from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes


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