import os
import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


logger = logging.getLogger()
logger.setLevel('INFO')


def generate_asym_data() -> tuple:
    """
    Функция генерирует ключи для асимметричного шифрования
    :return: закрытый ключ и открытый ключ
    """
    keys = rsa.generate_secret_key(public_exponent=65537, key_size=2048)
    secret_key = keys
    public_key = keys.public_key()
    logging.info(' Key generated for symmetric encryption')
    return secret_key, public_key


def generate_sym_data(len: int) -> str:
    """
    Функция генерирует ключ для симметричного шифрования
    :param len: длина ключа
    :return: ключ 
    """
    if len == 128 or len == 192 or len == 256:
        key = os.urandom(int(len/8))
        logging.info(
            ' Key generated for asymmetric encryption')
    else:
        logging.info(
            ' key lenght is not 128, 192, 256')
    return key

