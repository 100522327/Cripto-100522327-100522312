# app/crypto_symmetric.py

"""
Módulo para el cifrado y descifrado simétrico usando AES-GCM.
AES-GCM (Galois/Counter Mode) es un modo de cifrado autenticado que proporciona
confidencialidad, integridad y autenticidad de los datos en una sola operación.
"""

import os
import logging

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from config import SYMMETRIC_CONFIG

logger = logging.getLogger(__name__)

class SymmetricEncryptor:
    """Gestiona el cifrado y descifrado simétrico de datos."""

    def generate_key(self) -> bytes:
        """
        Genera una clave simétrica aleatoria y segura para AES.
        La longitud de la clave se define en el fichero de configuración.

        Returns:
            Una clave de N bytes (ej. 32 bytes para AES-256).
        """
        key_bytes = SYMMETRIC_CONFIG['KEY_SIZE'] // 8
        key = os.urandom(key_bytes)
        logger.debug(f"Clave AES de {SYMMETRIC_CONFIG['KEY_SIZE']} bits generada.")
        return key

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Cifra los datos proporcionados utilizando el algoritmo AES-GCM.

        El resultado incluye el 'nonce' (un número aleatorio usado una sola vez)
        y el 'tag' de autenticación, que son esenciales para un descifrado seguro.

        Args:
            data: Los bytes de información a cifrar (ej. el contenido de un fichero).
            key: La clave simétrica generada previamente.

        Returns:
            Un único objeto de bytes que contiene: nonce + ciphertext + tag.
        """
        # AESGCM requiere un nonce (número usado una sola vez) por cada operación de cifrado.
        # Debe ser aleatorio y único para cada mensaje cifrado con la misma clave.
        nonce = os.urandom(SYMMETRIC_CONFIG['NONCE_LENGTH'])
        
        aesgcm = AESGCM(key)
        
        # Cifrar los datos. El 'tag' de autenticación se genera y se añade al final.
        ciphertext = aesgcm.encrypt(nonce, data, None) # 'None' para datos no autenticados adicionales

        logger.info("Datos cifrados con AES-GCM.")
        logger.info(f"  - Algoritmo: AES-{SYMMETRIC_CONFIG['KEY_SIZE']} GCM")
        logger.info(f"  - Longitud de clave: {len(key) * 8} bits")
        
        # Se devuelve el nonce concatenado con el texto cifrado.
        # El descifrado necesitará saber dónde termina el nonce para separarlos.
        return nonce + ciphertext

    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Descifra los datos usando AES-GCM y verifica su integridad.

        Si los datos han sido manipulados o la clave es incorrecta,
        la verificación del 'tag' fallará y se lanzará una excepción.

        Args:
            encrypted_data: Los bytes cifrados (nonce + ciphertext + tag).
            key: La clave simétrica correcta.

        Returns:
            Los datos originales en texto plano.
        
        Raises:
            ValueError: Si el descifrado falla por cualquier motivo (datos corruptos, clave incorrecta).
        """
        nonce_len = SYMMETRIC_CONFIG['NONCE_LENGTH']
        
        # Separar el nonce del resto del payload
        nonce = encrypted_data[:nonce_len]
        ciphertext_with_tag = encrypted_data[nonce_len:]
        
        aesgcm = AESGCM(key)
        
        try:
            # Intentar descifrar. La librería verifica el tag automáticamente.
            decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            logger.info("Datos descifrados y verificados con AES-GCM correctamente.")
            return decrypted_data
        except Exception as e:
            # La excepción más común aquí es `cryptography.exceptions.InvalidTag`
            logger.error(f"Error de descifrado o fallo de integridad AES-GCM: {e}")
            raise ValueError("Descifrado fallido: los datos pueden estar corruptos o la clave es incorrecta.")