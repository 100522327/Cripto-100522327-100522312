"""
Módulo para cifrado y descifrado asimétrico usando RSA con padding OAEP.
Su principal función en este proyecto es proteger las claves simétricas.
"""

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.backends import default_backend

from config import ASYMMETRIC_CONFIG

logger = logging.getLogger(__name__)

class AsymmetricEncryptor:
    """Gestiona el cifrado/descifrado de datos (típicamente claves) con RSA."""

    def encrypt(self, data: bytes, public_key: RSAPublicKey) -> bytes:
        """
        Cifra datos (ej. una clave simétrica) usando la clave pública RSA de un destinatario.
        Cualquiera con la clave pública puede cifrar, pero solo el dueño de la clave privada puede descifrar.

        Utiliza padding OAEP, que es el estándar recomendado para evitar ataques.

        Args:
            data: Los bytes a cifrar (deben ser más pequeños que el tamaño de la clave RSA).
            public_key: El objeto de clave pública del destinatario.

        Returns:
            Los datos cifrados.
        """
        pad = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

        encrypted_data = public_key.encrypt(data, pad)

        logger.info(f"Datos cifrados con RSA-{public_key.key_size} y padding OAEP-SHA256.")
        return encrypted_data

    def decrypt(self, encrypted_data: bytes, private_key: RSAPrivateKey) -> bytes:
        """
        Descifra datos usando la clave privada RSA del usuario.

        Args:
            encrypted_data: Los datos que fueron cifrados con la clave pública correspondiente.
            private_key: El objeto de clave privada del usuario.

        Returns:
            Los datos originales descifrados.
            
        Raises:
            ValueError: Si el descifrado falla.
        """
        # El padding debe ser exactamente el mismo que se usó para cifrar.
        pad = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        
        try:
            decrypted_data = private_key.decrypt(encrypted_data, pad)
            logger.info(f"Datos descifrados con RSA-{private_key.key_size} correctamente.")
            return decrypted_data
        except Exception as e:
            logger.error(f"Error de descifrado asimétrico: {e}")
            raise ValueError("Descifrado RSA fallido. La clave privada podría ser incorrecta o los datos están corruptos.")