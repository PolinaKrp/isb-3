import os
import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


logger = logging.getLogger()
logger.setLevel('INFO')


def encrypt_asym_data(public_key, text: bytes) -> bytes:
    """
    Функция производит асимметричное шифрование по открытому ключу
    :param text: текст, который шифруем
    :param public_key: открытый ключ
    :return: зашифрованный текст
    """
    try:
        encrypted_text = public_key.encrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(), label=None))
        logging.info(f' The text is encrypted with an asymmetric encryption algorithm!')
    except OSError as err:
        logging.warning(f'Asymmetric encryption error! {err}')
    return encrypted_text


def encrypt_sym(key: bytes, text: bytes, len: int) -> bytes:
    """
    Функция шифрует текст алгоритмом симметричного шифрования Camellia
    :param len: длина ключа
    :param text: текст, который шифруем
    :param key: ключ
    :return: зашифрованный текст
    """
    try:
        padder = padding.ANSIX923(len).padder()
        padded_text = padder.update(text) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_text) + encryptor.finalize()
        logging.info(f' The text is encrypted with the Camellia symmetric encryption algorithm!')
    except OSError as err:
        logging.warning(f' Symmetric encryption error! {err}')
    return iv + cipher_text