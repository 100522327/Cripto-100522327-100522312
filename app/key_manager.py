"""
Módulo para la gestión de claves asimétricas (RSA) de los usuarios.
"""

import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from config import ASYMMETRIC_CONFIG, USERS_DIR

logger = logging.getLogger(__name__)

class KeyManager:
    """Gestiona la generación, almacenamiento y carga de pares de claves RSA."""

    def get_user_key_paths(self, username: str) -> tuple[Path, Path]:
        """Devuelve las rutas a los archivos de clave pública y privada del usuario."""
        user_dir = USERS_DIR / username
        user_dir.mkdir(exist_ok=True)
        private_key_path = user_dir / "private_key.pem"
        public_key_path = user_dir / "public_key.pem"
        return private_key_path, public_key_path

    def generate_and_save_key_pair(self, username: str, password: str) -> bool:
        """
        Genera un nuevo par de claves RSA y lo guarda en archivos PEM.
        La clave privada se cifra con la contraseña del usuario.

        Args:
            username: El nombre del usuario.
            password: La contraseña del usuario para cifrar la clave privada.

        Returns:
            True si las claves se generaron y guardaron, False en caso contrario.
        """
        private_key_path, public_key_path = self.get_user_key_paths(username)

        if private_key_path.exists() or public_key_path.exists():
            logger.warning(f"El par de claves para {username} ya existe.")
            return False

        try:
            logger.info(f"Generando par de claves RSA de {ASYMMETRIC_CONFIG['KEY_SIZE']} bits para {username}...")
            private_key = rsa.generate_private_key(
                public_exponent=ASYMMETRIC_CONFIG['PUBLIC_EXPONENT'],
                key_size=ASYMMETRIC_CONFIG['KEY_SIZE'],
                backend=default_backend()
            )

            # Cifrar la clave privada con la contraseña del usuario (estándar PKCS8)
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))

            # Serializar y guardar la clave privada cifrada
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algorithm
                ))
            
            logger.info(f"Clave privada para {username} guardada y cifrada.")

            # Serializar y guardar la clave pública
            public_key = private_key.public_key()
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            logger.info(f"Clave pública para {username} guardada.")
            return True

        except Exception as e:
            logger.error(f"Error generando el par de claves para {username}: {e}", exc_info=True)
            return False

    def load_public_key(self, username: str):
        """Carga la clave pública de un usuario desde su archivo."""
        _, public_key_path = self.get_user_key_paths(username)
        if not public_key_path.exists():
            logger.error(f"No se encontró la clave pública para {username}.")
            return None
        
        with open(public_key_path, "rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def load_private_key(self, username: str, password: str):
        """Carga y descifra la clave privada de un usuario usando su contraseña."""
        private_key_path, _ = self.get_user_key_paths(username)
        if not private_key_path.exists():
            logger.error(f"No se encontró la clave privada para {username}.")
            return None

        with open(private_key_path, "rb") as f:
            try:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode('utf-8'),
                    backend=default_backend()
                )
            except ValueError:
                logger.error(f"Error al descifrar la clave privada de {username}. Contraseña incorrecta.")
                return None
            except Exception as e:
                logger.error(f"Error inesperado cargando la clave privada de {username}: {e}")
                return None