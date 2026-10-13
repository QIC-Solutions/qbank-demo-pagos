"""Huella de los ficheros de liquidación que se envían al banco corresponsal."""

import hashlib


def huella_liquidacion(contenido: bytes) -> str:
    return hashlib.md5(contenido).hexdigest()


def huella_archivo_contratos(contenido: bytes) -> str:
    return hashlib.sha1(contenido).hexdigest()
