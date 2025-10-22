"""
Configuración global de la aplicación SecureSend
Contiene constantes y parámetros de configuración para todas las operaciones criptográficas
"""

import os
from pathlib import Path

# Directorios base
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
PKI_DIR = DATA_DIR / "pki"
USERS_DIR = DATA_DIR / "users"
DOCUMENTS_DIR = DATA_DIR / "documents"
LOGS_DIR = DATA_DIR / "logs"

# Crear directorios si no existen
for directory in [DATA_DIR, PKI_DIR, USERS_DIR, DOCUMENTS_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Subdirectorios PKI
CA_ROOT_DIR = PKI_DIR / "ca_root"
CA_SUB_DIR = PKI_DIR / "ca_sub"
USER_CERTS_DIR = PKI_DIR / "user_certs"

for directory in [CA_ROOT_DIR, CA_SUB_DIR, USER_CERTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Archivo de base de datos de usuarios
USERS_DB_FILE = USERS_DIR / "users.json"

# Configuración de autenticación
AUTH_CONFIG = {
    'HASH_ALGORITHM': 'sha256',  # Algoritmo de hash para contraseñas
    'SALT_LENGTH': 32,  # Longitud del salt en bytes
    'PBKDF2_ITERATIONS': 600000,  # Iteraciones para PBKDF2 (OWASP 2023 recommendation)
    'MIN_PASSWORD_LENGTH': 8,  # Longitud mínima de contraseña
    'DERIVED_KEY_LENGTH': 32,  # Longitud de la clave derivada (256 bits)
}

# Configuración de cifrado simétrico
SYMMETRIC_CONFIG = {
    'ALGORITHM': 'AES',
    'MODE': 'GCM',  # Galois/Counter Mode (cifrado autenticado)
    'KEY_SIZE': 256,  # bits
    'NONCE_LENGTH': 12,  # bytes (96 bits recomendado para GCM)
    'TAG_LENGTH': 16,  # bytes (128 bits)
}

# Configuración de cifrado asimétrico
ASYMMETRIC_CONFIG = {
    'ALGORITHM': 'RSA',
    'KEY_SIZE': 2048,  # bits (mínimo recomendado)
    'PUBLIC_EXPONENT': 65537,
    'PADDING': 'OAEP',  # Optimal Asymmetric Encryption Padding
    'HASH_ALGORITHM': 'SHA256',
}

# Configuración de firma digital
SIGNATURE_CONFIG = {
    'ALGORITHM': 'RSA',
    'KEY_SIZE': 2048,  # bits
    'HASH_ALGORITHM': 'SHA256',
    'PADDING': 'PSS',  # Probabilistic Signature Scheme
}

# Configuración HMAC
HMAC_CONFIG = {
    'ALGORITHM': 'SHA256',
    'KEY_LENGTH': 32,  # bytes (256 bits)
}

# Configuración de logging
LOG_CONFIG = {
    'LOG_FILE': LOGS_DIR / 'securesend.log',
    'LOG_LEVEL': 'INFO',
    'LOG_FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'DATE_FORMAT': '%Y-%m-%d %H:%M:%S',
}

# Configuración de PKI
PKI_CONFIG = {
    'ROOT_CA_VALIDITY_DAYS': 3650,  # 10 años
    'SUB_CA_VALIDITY_DAYS': 1825,   # 5 años
    'USER_CERT_VALIDITY_DAYS': 365,  # 1 año
    'KEY_SIZE': 2048,
    'HASH_ALGORITHM': 'SHA256',
}

# Información de la organización (para certificados)
ORG_INFO = {
    'COUNTRY': 'ES',
    'STATE': 'Madrid',
    'LOCALITY': 'Madrid',
    'ORGANIZATION': 'SecureSend',
    'ROOT_CN': 'SecureSend Root CA',
    'SUB_CN': 'SecureSend Subordinate CA',
}