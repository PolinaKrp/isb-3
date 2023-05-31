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
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    secret_key = keys
    public_key = keys.public_key()
    logging.info(' Key generated for asymmetric encryption')
    return secret_key, public_key


def generate_sym_data(len: int) -> str:
    """
    Функция генерирует ключ для симметричного шифрования
    :param len: длина ключа
    :return: ключ 
    """
    key = None
    choices = [128, 192, 256]
    if len in choices:
        key = os.urandom(int(len / 8))
        logging.info(' Symmetric encryption key generated')
    else:
        logging.warning(' The length of the key is not in choices: {}'.format(choices))
        raise ValueError(f'The length of the key {len} is not allowed')