import os
import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


logger = logging.getLogger()
logger.setLevel('INFO')


def decrypt_asym_data(secret_key, text: bytes) -> bytes:
    """
    Функция расшифровывает асимметрично зашифрованный текст, с помощью закрытого ключа
    :param text: зашифрованный текст
    :param secret_key: закрытый ключ
    :return: расшифрованный текст
    """
    try:
        decrypted_text = secret_key.decrypt(text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                algorithm=hashes.SHA256(), label=None))
        logging.info(f' The text encrypted with the asymmetric encryption algorithm has been decrypted!')
    except OSError as err:
        logging.warning(f' Asymmetric decryption error! {err}')
    return decrypted_text


def decrypt_sym(key: bytes, cipher_text: bytes, len: int) -> bytes:
    """
    Функция расшифровывает симметрично зашифрованный текст
    :param len: длина ключа
    :param cipher_text: зашифрованный текст
    :param key: ключ
    :return: возвращает расшифрованный текст
    """
    try:
        cipher_text, iv = cipher_text[16:], cipher_text[:16]
        cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        text = decryptor.update(cipher_text) + decryptor.finalize()
        unpadder = padding.ANSIX923(len).unpadder()
        unpadded_text = unpadder.update(text) + unpadder.finalize()
        logging.info(f' The text encrypted with Camellia"s symmetric encryption algorithm has been decrypted!')
    except OSError as err:
        logging.warning(f' Symmetric decryption error! {err}')
    return unpadded_text