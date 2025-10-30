import unittest
import sys
import shutil
from pathlib import Path

# Añadir el directorio raíz al path para poder importar módulos de 'app' y 'config'
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.key_manager import KeyManager
from config import USERS_DIR
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

class TestKeyManager(unittest.TestCase):
    """Tests para la clase KeyManager."""

    def setUp(self):
        """Se ejecuta antes de cada test para preparar el entorno."""
        self.key_manager = KeyManager()
        self.test_user = "test_key_user"
        self.test_password = "TestPassword123"
        self.user_dir = USERS_DIR / self.test_user
        # Limpiar cualquier resto de un test anterior
        if self.user_dir.exists():
            shutil.rmtree(self.user_dir)
        self.user_dir.mkdir()

    def tearDown(self):
        """Se ejecuta después de cada test para limpiar."""
        if self.user_dir.exists():
            shutil.rmtree(self.user_dir)

    def test_generate_and_save_key_pair_success(self):
        """Test: Generación y guardado exitoso de un par de claves."""
        print("\n[TEST] Generación exitosa de par de claves")
        
        result = self.key_manager.generate_and_save_key_pair(self.test_user, self.test_password)
        
        self.assertTrue(result)
        private_key_path, public_key_path = self.key_manager.get_user_key_paths(self.test_user)
        self.assertTrue(private_key_path.exists())
        self.assertTrue(public_key_path.exists())
        print("   ✓ Claves privada y pública creadas correctamente.")

    def test_load_private_key_success(self):
        """Test: Cargar una clave privada con la contraseña correcta."""
        print("\n[TEST] Carga de clave privada con contraseña correcta")
        
        self.key_manager.generate_and_save_key_pair(self.test_user, self.test_password)
        private_key = self.key_manager.load_private_key(self.test_user, self.test_password)
        
        self.assertIsNotNone(private_key)
        self.assertIsInstance(private_key, RSAPrivateKey)
        print("   ✓ Clave privada cargada y descifrada exitosamente.")

    def test_load_private_key_wrong_password(self):
        """Test: Falla al cargar clave privada con contraseña incorrecta."""
        print("\n[TEST] Carga de clave privada con contraseña incorrecta")
        
        self.key_manager.generate_and_save_key_pair(self.test_user, self.test_password)
        private_key = self.key_manager.load_private_key(self.test_user, "WrongPassword")
        
        self.assertIsNone(private_key)
        print("   ✓ La carga falló como se esperaba.")

    def test_load_public_key_success(self):
        """Test: Cargar una clave pública exitosamente."""
        print("\n[TEST] Carga de clave pública")

        self.key_manager.generate_and_save_key_pair(self.test_user, self.test_password)
        public_key = self.key_manager.load_public_key(self.test_user)

        self.assertIsNotNone(public_key)
        self.assertIsInstance(public_key, RSAPublicKey)
        print("   ✓ Clave pública cargada exitosamente.")

    def test_generate_keys_already_exist(self):
        """Test: Intento de generar claves cuando ya existen."""
        print("\n[TEST] Intento de sobreescribir claves existentes")

        # Primera generación, debe tener éxito
        self.key_manager.generate_and_save_key_pair(self.test_user, self.test_password)
        
        # Segundo intento, debe fallar
        result = self.key_manager.generate_and_save_key_pair(self.test_user, self.test_password)
        
        self.assertFalse(result)
        print("   ✓ La regeneración fue prevenida correctamente.")

if __name__ == '__main__':
    unittest.main(verbosity=2)