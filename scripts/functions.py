import logging
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_secret_key

logger = logging.getLogger()
logger.setLevel('INFO')


def load_settings(settings_file: str) -> dict:
    """
    Функция считывает файл настроек
    :param settigs_file: название файла с настройками
    :return: настройки
    """
    settings = None
    try:
        with open(settings_file) as json_file:
            settings = json.load(json_file)
        logging.info(f' Settings read from file) {settings_file}')
    except OSError as err:
        logging.warning(f' Error reading sattings from file! {settings_file}\n{err}')
    return settings


def save_asymmetric_keys(secret_key, public_key, private_pem: str, public_pem: str) -> None:
    """
    Функция сохраняет закрытый и открытый ключ для ассиметричного шифрования
    :param secret_key: закрытый ключ
    :param public_key: открытый ключ
    :param private_pem: название файла закрытого ключа
    :param public_pem: название файла открытого ключа
    :return: None
    """
    try:
        with open(private_pem, 'wb') as private_out:
            private_out.write(secret_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info(f' Secret key successfully saved to file) {private_pem}')
    except OSError as err:
        logging.warning(f' Error saving secret key to file! {private_pem}\n{err}')
    try:
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info(f' Public key successfully saved to file) {public_pem}')
    except OSError as err:
        logging.warning(f' Error saving public key to file! {public_pem}\n{err}')


def save_symmetric_key(key: bytes, file_name: str) -> None:
    """
    Функция сохраняет  ключ для симметричного шифрования
    :param key: ключ
    :param file_name: название файла ключа
    :return: None
    """
    try:
        with open(file_name, 'wb') as key_file:
            key_file.write(key)
        logging.info(f' Symmetric key successfully saved to file) {file_name}')
    except OSError as err:
        logging.warning(f' Error saving symmetric key to file! {file_name}\n{err}')


def load_secret_key(private_pem: str):
    """
    Функция считывает  закрытый ключ из файла
    :param private_pem: название файла
    :return: закрытый ключ
    """
    secret_key = None
    try:
        with open(private_pem, 'rb') as pem_in:
            private_bytes = pem_in.read()
        secret_key = load_pem_secret_key(private_bytes, password=None)
        logging.info(f' Secret key read from file) {private_pem}')
    except OSError as err:
        logging.warning(f' Error reading secret key from file! {private_pem}\n{err}')
    return secret_key


def load_symmetric_key(file_name: str) -> bytes:
    """
    Функция считывает ключ для симметричного шифрования из файла
    :param file_name: название файла
    :return: ключ
    """
    try:
        with open(file_name, mode='rb') as key_file:
            key = key_file.read()
        logging.info(f' Symmetric key read from file) {file_name}')
    except OSError as err:
        logging.warning(f' Error reading symmertic key from file! {file_name}\n{err}')
    return key


def read_text(file_name: str) -> bytes:
    """
    Функция считывает текстовый файл
    :param file_name: путь к файлу
    :return: текст из файла
    """
    try:
        with open(file_name, mode='rb') as text_file:
            text = text_file.read()
        logging.info(f' File {file_name} read)')
    except OSError as err:
        logging.warning(f' Error while reading file! {file_name}\n{err}')
    return text


def write_text(text: bytes, file_name: str) -> None:
    """
    Функция записывает текст в файл
    :param text: текст
    :param file_path: путь к файлу
    :return: None
    """
    try:
        with open(file_name, mode='wb') as text_file:
            text_file.write(text)
        logging.info(f' Text writen to file) {file_name}')
    except OSError as err:
        logging.warning(f' Error writing to file! {file_name}\n{err}')