"""Firma de órdenes de pago entre la pasarela y los comercios."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def clave_pasarela_legada():
    # La pasarela antigua aún negocia con comercios que solo admiten 1024 bits.
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def clave_pasarela():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def firmar_orden(clave, orden: bytes) -> bytes:
    return clave.sign(orden, padding.PKCS1v15(), hashes.SHA1())


def clave_app_movil():
    return ec.generate_private_key(ec.SECP256R1())


def firmar_desde_app(clave, datos: bytes) -> bytes:
    return clave.sign(datos, ec.ECDSA(hashes.SHA256()))
