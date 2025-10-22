"""
Módulo de autenticación de usuarios para SecureSend
Implementa registro y autenticación basada en contraseñas con almacenamiento seguro
"""

import json
import os
import secrets
import hashlib
from pathlib import Path
from typing import Optional, Dict, Tuple
import logging
from datetime import datetime

from config import (
    USERS_DB_FILE,
    AUTH_CONFIG,
    USERS_DIR
)

# Configurar logging
logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Excepción personalizada para errores de autenticación"""
    pass


class UserAlreadyExistsError(Exception):
    """Excepción cuando se intenta registrar un usuario que ya existe"""
    pass


class AuthManager:
    """
    Gestor de autenticación de usuarios
    Maneja el registro, login y almacenamiento seguro de credenciales
    """

    def __init__(self):
        """Inicializa el gestor de autenticación"""
        self.users_db_path = USERS_DB_FILE
        self._load_users_db()
        logger.info("AuthManager inicializado correctamente")

    def _load_users_db(self):
        """Carga la base de datos de usuarios desde archivo JSON"""
        if self.users_db_path.exists():
            try:
                with open(self.users_db_path, 'r', encoding='utf-8') as f:
                    self.users_db = json.load(f)
                logger.info(f"Base de datos cargada: {len(self.users_db)} usuarios")
            except json.JSONDecodeError:
                logger.warning("Archivo de usuarios corrupto, creando nueva base de datos")
                self.users_db = {}
        else:
            self.users_db = {}
            logger.info("Nueva base de datos de usuarios creada")

    def _save_users_db(self):
        """Guarda la base de datos de usuarios en archivo JSON"""
        try:
            with open(self.users_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.users_db, f, indent=2, ensure_ascii=False)
            logger.info("Base de datos de usuarios guardada correctamente")
        except Exception as e:
            logger.error(f"Error al guardar base de datos: {e}")
            raise

    def _generate_salt(self) -> str:
        """
        Genera un salt aleatorio para el hash de contraseñas

        Returns:
            Salt en formato hexadecimal
        """
        salt_bytes = secrets.token_bytes(AUTH_CONFIG['SALT_LENGTH'])
        salt_hex = salt_bytes.hex()
        logger.debug(f"Salt generado de {AUTH_CONFIG['SALT_LENGTH']} bytes")
        return salt_hex

    def _hash_password(self, password: str, salt: str) -> str:
        """
        Genera el hash de una contraseña usando PBKDF2

        PBKDF2 (Password-Based Key Derivation Function 2) es un algoritmo
        diseñado específicamente para derivar claves desde contraseñas,
        añadiendo resistencia contra ataques de fuerza bruta mediante
        múltiples iteraciones.

        Args:
            password: Contraseña en texto plano
            salt: Salt en formato hexadecimal

        Returns:
            Hash de la contraseña en formato hexadecimal
        """
        salt_bytes = bytes.fromhex(salt)

        # PBKDF2 con HMAC-SHA256
        key = hashlib.pbkdf2_hmac(
            AUTH_CONFIG['HASH_ALGORITHM'],
            password.encode('utf-8'),
            salt_bytes,
            AUTH_CONFIG['PBKDF2_ITERATIONS'],
            dklen=AUTH_CONFIG['DERIVED_KEY_LENGTH']
        )

        hash_hex = key.hex()

        logger.info(f"Hash generado usando PBKDF2-HMAC-{AUTH_CONFIG['HASH_ALGORITHM'].upper()}")
        logger.info(f"Iteraciones: {AUTH_CONFIG['PBKDF2_ITERATIONS']}")
        logger.info(f"Longitud de clave derivada: {AUTH_CONFIG['DERIVED_KEY_LENGTH']} bytes")

        return hash_hex

    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """
        Valida que la contraseña cumpla con requisitos mínimos de seguridad

        Args:
            password: Contraseña a validar

        Returns:
            Tupla (es_válida, mensaje_error)
        """
        if len(password) < AUTH_CONFIG['MIN_PASSWORD_LENGTH']:
            return False, f"La contraseña debe tener al menos {AUTH_CONFIG['MIN_PASSWORD_LENGTH']} caracteres"

        # Verificar que contiene al menos una letra mayúscula
        if not any(c.isupper() for c in password):
            return False, "La contraseña debe contener al menos una letra mayúscula"

        # Verificar que contiene al menos una letra minúscula
        if not any(c.islower() for c in password):
            return False, "La contraseña debe contener al menos una letra minúscula"

        # Verificar que contiene al menos un dígito
        if not any(c.isdigit() for c in password):
            return False, "La contraseña debe contener al menos un número"

        return True, ""

    def register_user(self, username: str, password: str, email: str,
                      role: str = "user") -> Dict:
        """
        Registra un nuevo usuario en el sistema

        Args:
            username: Nombre de usuario único
            password: Contraseña en texto plano
            email: Correo electrónico del usuario
            role: Rol del usuario ("user" o "professional")

        Returns:
            Diccionario con información del usuario registrado

        Raises:
            UserAlreadyExistsError: Si el usuario ya existe
            ValueError: Si la contraseña no cumple requisitos de seguridad
        """
        logger.info(f"Intentando registrar usuario: {username}")

        # Verificar que el usuario no existe
        if username in self.users_db:
            logger.warning(f"Intento de registro fallido: usuario '{username}' ya existe")
            raise UserAlreadyExistsError(f"El usuario '{username}' ya existe")

        # Validar fortaleza de contraseña
        is_valid, error_msg = self._validate_password_strength(password)
        if not is_valid:
            logger.warning(f"Contraseña débil para usuario '{username}': {error_msg}")
            raise ValueError(error_msg)

        # Generar salt único para este usuario
        salt = self._generate_salt()

        # Generar hash de la contraseña
        password_hash = self._hash_password(password, salt)

        # Crear registro de usuario
        user_data = {
            'username': username,
            'email': email,
            'role': role,
            'salt': salt,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'has_keypair': False,  # Se actualizará cuando se genere el par de claves
            'certificate_issued': False  # Se actualizará cuando se emita el certificado
        }

        # Guardar en la base de datos
        self.users_db[username] = user_data
        self._save_users_db()

        # Crear directorio personal del usuario
        user_dir = USERS_DIR / username
        user_dir.mkdir(exist_ok=True)

        logger.info(f"Usuario '{username}' registrado exitosamente")
        logger.info(f"  - Email: {email}")
        logger.info(f"  - Rol: {role}")
        logger.info(f"  - Algoritmo: PBKDF2-HMAC-{AUTH_CONFIG['HASH_ALGORITHM'].upper()}")

        # No devolver información sensible
        return {
            'username': username,
            'email': email,
            'role': role,
            'created_at': user_data['created_at']
        }

    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Autentica un usuario verificando sus credenciales

        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano

        Returns:
            True si las credenciales son correctas, False en caso contrario
        """
        logger.info(f"Intento de autenticación para usuario: {username}")

        # Verificar que el usuario existe
        if username not in self.users_db:
            logger.warning(f"Intento de login fallido: usuario '{username}' no existe")
            return False

        user_data = self.users_db[username]

        # Obtener salt y hash almacenados
        salt = user_data['salt']
        stored_hash = user_data['password_hash']

        # Calcular hash de la contraseña proporcionada
        provided_hash = self._hash_password(password, salt)

        # Comparación segura contra timing attacks
        is_valid = secrets.compare_digest(provided_hash, stored_hash)

        if is_valid:
            # Actualizar último login
            user_data['last_login'] = datetime.now().isoformat()
            self._save_users_db()
            logger.info(f"Autenticación exitosa para usuario: {username}")
        else:
            logger.warning(f"Autenticación fallida para usuario: {username}")

        return is_valid

    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Obtiene información de un usuario (sin datos sensibles)

        Args:
            username: Nombre de usuario

        Returns:
            Diccionario con información del usuario o None si no existe
        """
        if username not in self.users_db:
            return None

        user_data = self.users_db[username]

        # Devolver solo información no sensible
        return {
            'username': user_data['username'],
            'email': user_data['email'],
            'role': user_data['role'],
            'created_at': user_data['created_at'],
            'last_login': user_data['last_login'],
            'has_keypair': user_data['has_keypair'],
            'certificate_issued': user_data['certificate_issued']
        }

    def update_user_keypair_status(self, username: str, has_keypair: bool):
        """
        Actualiza el estado de generación de par de claves del usuario

        Args:
            username: Nombre de usuario
            has_keypair: True si el usuario ya tiene par de claves generado
        """
        if username in self.users_db:
            self.users_db[username]['has_keypair'] = has_keypair
            self._save_users_db()
            logger.info(f"Estado keypair actualizado para {username}: {has_keypair}")

    def update_user_certificate_status(self, username: str, certificate_issued: bool):
        """
        Actualiza el estado de emisión de certificado del usuario

        Args:
            username: Nombre de usuario
            certificate_issued: True si el certificado ha sido emitido
        """
        if username in self.users_db:
            self.users_db[username]['certificate_issued'] = certificate_issued
            self._save_users_db()
            logger.info(f"Estado certificado actualizado para {username}: {certificate_issued}")

    def list_users(self) -> list:
        """
        Lista todos los usuarios registrados (sin información sensible)

        Returns:
            Lista de diccionarios con información de usuarios
        """
        return [self.get_user_info(username) for username in self.users_db.keys()]


# Función de utilidad para testing
def test_auth_module():
    """Función de prueba del módulo de autenticación"""
    print("=== TEST DEL MÓDULO DE AUTENTICACIÓN ===\n")

    auth = AuthManager()

    # Test 1: Registro de usuario
    print("1. Registrando usuario de prueba...")
    try:
        user_info = auth.register_user(
            username="doctor_garcia",
            password="SecurePass123",
            email="garcia@clinic.com",
            role="professional"
        )
        print(f"   ✓ Usuario registrado: {user_info['username']}")
    except UserAlreadyExistsError:
        print("   ✓ Usuario ya existe (test previo)")
    except Exception as e:
        print(f"   ✗ Error: {e}")

    # Test 2: Contraseña débil
    print("\n2. Probando registro con contraseña débil...")
    try:
        auth.register_user("test_weak", "123", "test@test.com")
        print("   ✗ No se detectó contraseña débil")
    except ValueError as e:
        print(f"   ✓ Contraseña débil detectada: {e}")

    # Test 3: Autenticación correcta
    print("\n3. Probando autenticación con credenciales correctas...")
    if auth.authenticate_user("doctor_garcia", "SecurePass123"):
        print("   ✓ Autenticación exitosa")
    else:
        print("   ✗ Autenticación fallida")

    # Test 4: Autenticación incorrecta
    print("\n4. Probando autenticación con contraseña incorrecta...")
    if not auth.authenticate_user("doctor_garcia", "WrongPassword"):
        print("   ✓ Autenticación fallida correctamente")
    else:
        print("   ✗ Se aceptó contraseña incorrecta")

    # Test 5: Obtener información de usuario
    print("\n5. Obteniendo información de usuario...")
    user_info = auth.get_user_info("doctor_garcia")
    if user_info:
        print(f"   ✓ Usuario: {user_info['username']}")
        print(f"     Email: {user_info['email']}")
        print(f"     Rol: {user_info['role']}")

    print("\n=== FIN DE LOS TESTS ===")


if __name__ == "__main__":
    # Configurar logging básico para pruebas
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    test_auth_module()