"""
Módulo para la generación y verificación de Firmas Digitales.
Utiliza RSA con padding PSS (Probabilistic Signature Scheme) para máxima seguridad.
Cumple con el requisito de garantizar Autenticidad, No Repudio e Integridad.
"""

import logging
from typing import Optional, Tuple

# Importaciones de criptografía
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.exceptions import InvalidSignature

# Importaciones del proyecto
from key_manager import KeyManager
# Asumimos que existen estas configuraciones, si no, se usan defaults
try:
    from config import SIGNATURE_CONFIG
except ImportError:
    # Configuración por defecto si no está en config.py
    SIGNATURE_CONFIG = {'HASH_ALGORITHM': 'SHA256'}

logger = logging.getLogger(__name__)

class SignatureManager:
    """
    Gestor de firmas digitales.
    Permite firmar documentos (bytes) con clave privada y verificarlos con clave pública.
    """

    def __init__(self):
        self.key_manager = KeyManager()
        logger.info("SignatureManager inicializado")

    def sign_document(self, data: bytes, username: str, password: str) -> Optional[bytes]:
        """
        Genera una firma digital para un documento.
        
        Pasos:
        1. Carga la clave privada del usuario (requiere contraseña).
        2. Aplica un hash al documento (SHA-256).
        3. Cifra el hash con la clave privada (Firma).

        Args:
            data: Contenido del archivo/documento a firmar en bytes.
            username: Usuario que firma.
            password: Contraseña para descifrar su clave privada.

        Returns:
            bytes: La firma digital o None si hubo error.
        """
        logger.info(f"Iniciando proceso de firma para usuario: {username}")

        # 1. Cargar clave privada
        private_key = self.key_manager.load_private_key(username, password)
        if not private_key:
            logger.error(f"No se pudo cargar la clave privada de {username}. Abortando firma.")
            return None

        try:
            # 2. y 3. Hashing y Firma
            # Usamos PSS (Probabilistic Signature Scheme) que es más robusto que PKCS1v15
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            logger.info("Documento firmado exitosamente.")
            logger.info(f"  - Algoritmo de Hashing: {SIGNATURE_CONFIG.get('HASH_ALGORITHM', 'SHA256')}")
            logger.info(f"  - Algoritmo de Firma: RSA-PSS")
            logger.info(f"  - Longitud de clave: {private_key.key_size} bits")
            
            return signature

        except Exception as e:
            logger.error(f"Error durante la generación de la firma: {e}")
            return None

    def verify_signature(self, data: bytes, signature: bytes, signer_username: str) -> bool:
        """
        Verifica la firma digital de un documento.

        Pasos:
        1. Carga la clave pública del supuesto firmante.
        2. Recalcula el hash del documento.
        3. Descifra la firma con la clave pública y compara los hashes.

        Args:
            data: El contenido original del documento.
            signature: La firma digital a verificar.
            signer_username: El nombre del usuario que supuestamente firmó (para cargar su clave pública).

        Returns:
            bool: True si la firma es válida, False si no lo es.
        """
        logger.info(f"Verificando firma del usuario: {signer_username}")

        # 1. Cargar clave pública
        public_key = self.key_manager.load_public_key(signer_username)
        if not public_key:
            logger.error(f"No se encontró clave pública para {signer_username}.")
            return False

        try:
            # 2. y 3. Verificación
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info("Verificación de firma DIGITAL: ÉXITO. El documento es auténtico e íntegro.")
            return True

        except InvalidSignature:
            logger.warning("Verificación de firma DIGITAL: FALLO. La firma no coincide o el documento fue alterado.")
            return False
        except Exception as e:
            logger.error(f"Error inesperado durante la verificación: {e}")
            return False

# --- Bloque de pruebas unitarias ---
def test_signature_module():
    """Prueba rápida del módulo"""
    import os
    
    print("=== TEST DEL MÓDULO DE FIRMA DIGITAL ===")
    
    # Setup básico
    sig_manager = SignatureManager()
    km = KeyManager()
    user = "test_signer"
    pwd = "StrongPassword1!"
    
    # Asegurar que el usuario tiene claves para el test
    print(f"Generando claves temporales para {user}...")
    km.generate_and_save_key_pair(user, pwd)
    
    # Crear un documento falso
    doc_content = b"Este es un contrato confidencial muy importante."
    print(f"Documento original: {doc_content}")
    
    # 1. FIRMAR
    print("\n1. Firmando documento...")
    signature = sig_manager.sign_document(doc_content, user, pwd)
    
    if signature:
        print(f"   ✓ Firma generada (Longitud: {len(signature)} bytes)")
    else:
        print("   ✗ Error generando firma")
        return

    # 2. VERIFICAR (Caso Éxito)
    print("\n2. Verificando firma correcta...")
    is_valid = sig_manager.verify_signature(doc_content, signature, user)
    if is_valid:
        print("   ✓ Verificación exitosa")
    else:
        print("   ✗ Fallo en verificación válida")

    # 3. VERIFICAR (Caso Ataque de Integridad)
    print("\n3. Verificando documento manipulado...")
    doc_manipulado = b"Este es un contrato confidencial muy importante MODIFICADO."
    is_valid_fake = sig_manager.verify_signature(doc_manipulado, signature, user)
    if not is_valid_fake:
        print("   ✓ El sistema detectó la manipulación correctamente")
    else:
        print("   ✗ PELIGRO: El sistema aceptó un documento modificado")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
    test_signature_module()