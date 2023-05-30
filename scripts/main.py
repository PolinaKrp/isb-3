import argparse
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from decrypt import decrypt_asym_data, decrypt_sym
from encrypt import encrypt_asym_data, encrypt_sym
from generate import generate_asym_data, generate_sym_data
from functions import load_settings, save_asymmetric_keys, save_symmetric_key, load_secret_key, load_symmetric_key, read_text, write_text

SETTINGS = 'settings.json'

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-set', '--settings', default=SETTINGS, type=str, help='Позволяет использовать собственный json-файл с указанием путей'
                        '(Введите путь к файлу)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', nargs="?", const=256, type=int,
                       help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', nargs="?", const=256, type=int,
                       help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', nargs="?", const=256, type=int,
                       help='Запускает режим дешифрования')
    args = parser.parse_args()
    settings = load_settings(args.settings)
    if settings:
        if args.generation:
            symmetric_key = generate_sym_data(args.generation)
            private_key, public_key = generate_asym_data()
            save_asymmetric_keys(private_key, public_key,
                                 settings['secret_key'], settings['public_key'])
            cipher_symmetric_key = encrypt_asym_data(
                public_key, symmetric_key)
            save_symmetric_key(cipher_symmetric_key, settings['symmetric_key'])
        elif args.encryption:
            private_key = load_secret_key(settings['secret_key'])
            cipher_key = load_symmetric_key(settings['symmetric_key'])
            symmetric_key = decrypt_asym_data(private_key, cipher_key)
            text = read_text(settings['initial_file'])
            cipher_text = encrypt_sym(symmetric_key, text, args.encryption)
            write_text(cipher_text, settings['encrypted_file'])
        else:
            private_key = load_secret_key(settings['secret_key'])
            cipher_key = load_symmetric_key(settings['symmetric_key'])
            symmetric_key = decrypt_asym_data(private_key, cipher_key)
            cipher_text = read_text(settings['encrypted_file'])
            text = decrypt_sym(symmetric_key, cipher_text, args.decryption)
            write_text(text, settings['decrypted_file'])