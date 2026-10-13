"""Cifrado de datos de tarjeta en la conexión con los cajeros."""

import os

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes


def cifrar_pin_block(clave: bytes, bloque: bytes) -> bytes:
    # Los HSM de PIN de los cajeros siguen con 3DES hasta su renovación.
    iv = os.urandom(8)
    cifrador = Cipher(TripleDES(clave), modes.CBC(iv)).encryptor()
    return iv + cifrador.update(bloque) + cifrador.finalize()
