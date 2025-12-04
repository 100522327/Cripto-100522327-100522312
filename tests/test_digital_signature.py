import unittest
import shutil
import tempfile
import sys
import os
from pathlib import Path
from unittest.mock import patch

# Añadir el directorio 'app' al path para simular el entorno de main.py
# Esto permite que los módulos dentro de 'app' se vean entre sí (ej. key_manager)
app_path = Path(__file__).parent.parent / 'app'
sys.path.insert(0, str(app_path))

# Nota: Al añadir 'app' al path, importamos SIN el prefijo 'app.'
from digital_signature import SignatureManager
from key_manager import KeyManager

class TestDigitalSignature(unittest.TestCase):
    """
    Test suite para el módulo de Firma Digital.
    Verifica Autenticidad, Integridad y No Repudio.
    """

    def setUp(self):
        """Se ejecuta ANTES de cada test."""
        # 1. Crear un directorio temporal para simular 'data/users'
        self.test_dir = tempfile.mkdtemp()
        self.test_users_dir = Path(self.test_dir)
        
        # 2. Parchear USERS_DIR en key_manager para que apunte al directorio temporal
        #    Esto evita que los tests ensucien tu carpeta real de usuarios.
        self.patcher = patch('key_manager.USERS_DIR', self.test_users_dir)
        self.mock_users_dir = self.patcher.start()

        # 3. Inicializar los gestores
        self.sig_manager = SignatureManager()
        self.key_manager = KeyManager()

        # 4. Crear un usuario de prueba y sus claves
        self.username = "test_user_paco"
        self.password = "SecurePass123!"
        
        # Generar claves reales en el directorio temporal
        self.key_manager.generate_and_save_key_pair(self.username, self.password)

    def tearDown(self):
        """Se ejecuta DESPUÉS de cada test."""
        self.patcher.stop()
        shutil.rmtree(self.test_dir)  # Borrar el directorio temporal

    def test_sign_and_verify_success(self):
        """
        Caso de Éxito: Un documento firmado correctamente debe verificarse como válido.
        (Prueba de Autenticidad e Integridad)
        """
        data = b"Contenido importante del contrato."
        
        # 1. Firmar
        signature = self.sig_manager.sign_document(data, self.username, self.password)
        self.assertIsNotNone(signature, "La firma no debería ser None")
        
        # 2. Verificar
        is_valid = self.sig_manager.verify_signature(data, signature, self.username)
        self.assertTrue(is_valid, "La verificación debería ser exitosa para un documento inalterado")

    def test_verify_integrity_failure(self):
        """
        Caso de Fallo: Si el documento cambia un solo byte, la verificación debe fallar.
        (Prueba de Integridad)
        """
        original_data = b"Este es el mensaje original."
        modified_data = b"Este es el mensaje originl."  
        
        # 1. Firmar original
        signature = self.sig_manager.sign_document(original_data, self.username, self.password)
        
        # 2. Verificar con datos modificados
        is_valid = self.sig_manager.verify_signature(modified_data, signature, self.username)
        self.assertFalse(is_valid, "La verificación debe fallar si el documento ha sido modificado")

    def test_verify_authenticity_failure(self):
        """
        Caso de Fallo: Verificar una firma con la clave pública de OTRO usuario debe fallar.
        (Prueba de Autenticidad)
        """
        data = b"Mensaje confidencial."
        
        # Crear un segundo usuario atacante o erróneo
        attacker = "test_attacker"
        self.key_manager.generate_and_save_key_pair(attacker, "HackerPass1")

        # 1. El usuario legítimo firma el documento
        signature = self.sig_manager.sign_document(data, self.username, self.password)

        # 2. Intentamos verificar diciendo que lo firmó el atacante
        is_valid = self.sig_manager.verify_signature(data, signature, attacker)
        self.assertFalse(is_valid, "La verificación debe fallar si se usa la clave pública incorrecta")

    def test_sign_bad_password(self):
        """
        Caso de Fallo: Intentar firmar con contraseña incorrecta no debe generar firma.
        (Prueba de seguridad de la clave privada - No Repudio)
        """
        data = b"Intento de firma no autorizado."
        wrong_password = "WrongPassword"

        # Intentar firmar
        signature = self.sig_manager.sign_document(data, self.username, wrong_password)
        
        self.assertIsNone(signature, "La firma debe ser None si la contraseña es incorrecta")

    def test_signature_corruption(self):
        """
        Caso de Fallo: Si el archivo de firma (.sig) se corrompe, la verificación falla.
        """
        data = b"Datos validos."
        
        # 1. Generar firma válida
        signature = self.sig_manager.sign_document(data, self.username, self.password)
        
        # 2. Corromper la firma (cambiar el último byte)
        sig_list = bytearray(signature)
        sig_list[-1] = (sig_list[-1] + 1) % 256 
        corrupted_signature = bytes(sig_list)

        # 3. Verificar
        is_valid = self.sig_manager.verify_signature(data, corrupted_signature, self.username)
        self.assertFalse(is_valid, "La verificación debe fallar si la firma está corrupta")

if __name__ == '__main__':
    unittest.main()