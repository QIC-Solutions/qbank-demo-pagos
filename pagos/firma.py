"""Firma de órdenes de pago entre la pasarela y los comercios."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEM_ALG = "ML-KEM-768"  # NIST FIPS 203


def clave_pasarela_legada():
    # Eliminado: RSA-1024 no es quantum-safe ni cumple el minimo clasico.
    # Los comercios que solo admiten 1024 bits deben migrar al esquema hibrido;
    # no se genera material RSA debil bajo ninguna circunstancia.
    raise RuntimeError("RSA-1024 deshabilitado: usar clave_pasarela() (hibrido X25519 + ML-KEM-768)")


def clave_pasarela():
    # Esquema hibrido: X25519 (clasico) + ML-KEM-768 (post-cuantico).
    kem = oqs.KeyEncapsulation(KEM_ALG)
    pk_mlkem = kem.generate_keypair()
    sk_mlkem = kem.export_secret_key()
    sk_x25519 = x25519.X25519PrivateKey.generate()
    pk_x25519 = sk_x25519.public_key()
    return {
        "mlkem_pub": pk_mlkem,
        "mlkem_priv": sk_mlkem,
        "x25519_pub": pk_x25519,
        "x25519_priv": sk_x25519,
    }


def derivar_secreto_hibrido(ss_x25519: bytes, ss_mlkem: bytes) -> bytes:
    # Combina ambos secretos compartidos en una unica clave de sesion.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pasarela-pagos-hibrido-x25519-mlkem768",
    ).derive(ss_x25519 + ss_mlkem)


def firmar_orden(clave, orden: bytes) -> bytes:
    return clave.sign(orden, padding.PKCS1v15(), hashes.SHA1())  # TODO: migrar también esta firma RSA/SHA-1


def clave_app_movil():
    # Híbrido: ECDSA P-256 (clásico) + ML-DSA-65 (FIPS 204, post-cuántico)
    clave_ec = ec.generate_private_key(ec.SECP256R1())
    firmante_pqc = oqs.Signature("ML-DSA-65")
    pub_pqc = firmante_pqc.generate_keypair()
    return {"ec": clave_ec, "pqc": firmante_pqc, "pqc_pub": pub_pqc}


def firmar_desde_app(clave, datos: bytes) -> bytes:
    firma_ec = clave["ec"].sign(datos, ec.ECDSA(hashes.SHA256()))
    firma_pqc = clave["pqc"].sign(datos)
    # Firma híbrida: el verificador debe validar AMBAS firmas
    return len(firma_ec).to_bytes(2, "big") + firma_ec + firma_pqc
