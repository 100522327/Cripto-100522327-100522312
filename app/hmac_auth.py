
import os
import hmac
import logging
import secrets

from cryptography.hazmat.primitives import hashes

from config import HMAC_CONFIG

logger = logging.getLogger(__name__)

class HmacManager:
    """Gestiona la creación y verificación de HMACs."""

    def generate_key(self) -> bytes:
        """Genera una clave aleatoria para HMAC."""
        key = os.urandom(HMAC_CONFIG['KEY_LENGTH'])
        logger.debug(f"Clave HMAC de {HMAC_CONFIG['KEY_LENGTH']} bytes generada.")
        return key

    def generate_hmac(self, data: bytes, key: bytes) -> str:
        """
        Genera un HMAC para los datos proporcionados.
        
        Returns:
            El HMAC en formato hexadecimal.
        """
        hash_class = getattr(hashes, HMAC_CONFIG['ALGORITHM'].upper())
        
        
        # Una solución más simple y compatible con el módulo `hmac` estándar es usar `hashlib`:
        import hashlib
        hash_func = getattr(hashlib, HMAC_CONFIG['ALGORITHM'].lower())
        
        h = hmac.new(key, data, hash_func)
        
        hmac_hex = h.hexdigest()
        logger.info(f"HMAC generado con HMAC-{HMAC_CONFIG['ALGORITHM'].upper()}.")
        logger.info(f" 	- Longitud de clave: {len(key) * 8} bits")
        return hmac_hex

    def verify_hmac(self, data: bytes, key: bytes, expected_hmac: str) -> bool:
        """
        Verifica si el HMAC proporcionado es válido para los datos.
        Usa una comparación segura para evitar ataques de temporización.
        """
        generated_hmac = self.generate_hmac(data, key)
        is_valid = secrets.compare_digest(generated_hmac, expected_hmac)
        
        if is_valid:
            logger.info("Verificación de HMAC exitosa. La integridad de los datos está confirmada.")
        else:
            logger.warning("¡Verificación de HMAC fallida! Los datos pueden haber sido manipulados.")
            
        return is_valid