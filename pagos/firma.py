"""Firma de órdenes de pago entre la pasarela y los comercios."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def clave_pasarela_legada():
    # RSA-1024 retirado: no existe modo de compatibilidad seguro.
    # Los comercios que solo admitan 1024 bits deben migrar al canal híbrido.
    raise NotImplementedError("RSA-1024 retirado; usar clave_pasarela() (X25519 + ML-KEM-768)")


def clave_pasarela():
    # Esquema híbrido X25519 + ML-KEM-768 (FIPS 203)
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    mlkem_pub = kem.generate_keypair()
    x25519_priv = X25519PrivateKey.generate()
    return {
        "kem": kem,
        "mlkem_pub": mlkem_pub,
        "x25519_priv": x25519_priv,
        "x25519_pub": x25519_priv.public_key(),
    }


def secreto_compartido(kem, mlkem_ciphertext, x25519_priv, x25519_pub_comercio):
    # Combina ambos secretos: la sesión es segura si al menos uno de los dos resiste.
    ss_mlkem = kem.decap_secret(mlkem_ciphertext)
    ss_x25519 = x25519_priv.exchange(x25519_pub_comercio)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pasarela-pagos-hibrido-x25519-mlkem768",
    ).derive(ss_x25519 + ss_mlkem)


def firmar_orden(clave, orden: bytes) -> bytes:
    return clave.sign(orden, padding.PKCS1v15(), hashes.SHA1())  # TODO: hallazgo RSA/SHA1 aparte (migrar a híbrido PQC)


import oqs

ALG_FIRMA_PQC = "ML-DSA-65"  # NIST FIPS 204


def clave_app_movil():
    # Híbrido: ECDSA P-256 (clásico) + ML-DSA-65 (post-cuántico)
    clave_ec = ec.generate_private_key(ec.SECP256R1())
    firmante_pqc = oqs.Signature(ALG_FIRMA_PQC)
    pub_pqc = firmante_pqc.generate_keypair()
    return {"ec": clave_ec, "pqc": firmante_pqc, "pqc_pub": pub_pqc}


def firmar_desde_app(clave, datos: bytes) -> bytes:
    firma_ec = clave["ec"].sign(datos, ec.ECDSA(hashes.SHA256()))
    firma_pqc = clave["pqc"].sign(datos)
    # Firma híbrida: el verificador debe validar AMBAS (longitud ECDSA en 2 bytes de prefijo)
    return len(firma_ec).to_bytes(2, "big") + firma_ec + firma_pqc
