import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.hmac_auth import HmacManager
from config import HMAC_CONFIG

class TestHmacManager(unittest.TestCase):
    """Tests para la clase HmacManager."""

    def setUp(self):
        self.hmac_manager = HmacManager()
        self.data = b"Este es el contenido de un fichero cifrado."

    def test_generate_verify_hmac_success(self):
        """Test: Generar un HMAC y verificarlo con éxito."""
        print("\n[TEST] Generación y verificación de HMAC exitosa")
        key = self.hmac_manager.generate_key()
        hmac_tag = self.hmac_manager.generate_hmac(self.data, key)
        
        is_valid = self.hmac_manager.verify_hmac(self.data, key, hmac_tag)
        self.assertTrue(is_valid)
        print("   ✓ HMAC verificado correctamente.")
    
    def test_verify_hmac_wrong_key(self):
        """Test: La verificación HMAC debe fallar con la clave incorrecta."""
        print("\n[TEST] Verificación HMAC con clave incorrecta")
        key_a = self.hmac_manager.generate_key()
        key_b = self.hmac_manager.generate_key()
        hmac_tag = self.hmac_manager.generate_hmac(self.data, key_a)
        
        is_valid = self.hmac_manager.verify_hmac(self.data, key_b, hmac_tag)
        self.assertFalse(is_valid)
        print("   ✓ Verificación falló como se esperaba.")

    def test_verify_hmac_tampered_data(self):
        """Test: La verificación HMAC debe fallar si los datos son modificados."""
        print("\n[TEST] Verificación HMAC con datos manipulados")
        key = self.hmac_manager.generate_key()
        hmac_tag = self.hmac_manager.generate_hmac(self.data, key)
        
        tampered_data = self.data + b" un extra malicioso"
        
        is_valid = self.hmac_manager.verify_hmac(tampered_data, key, hmac_tag)
        self.assertFalse(is_valid)
        print("   ✓ Verificación falló como se esperaba.")

if __name__ == '__main__':
    unittest.main(verbosity=2)