import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.cifrado_simetrico import SymmetricEncryptor
from config import SYMMETRIC_CONFIG

class TestSymmetricEncryptor(unittest.TestCase):
    """Tests para la clase SymmetricEncryptor."""

    def setUp(self):
        self.encryptor = SymmetricEncryptor()
        self.original_data = b"Este es un documento confidencial con informacion sensible."
    
    def test_key_generation(self):
        """Test: La clave generada tiene la longitud correcta."""
        print("\n[TEST] Generación de clave simétrica")
        key = self.encryptor.generate_key()
        expected_len = SYMMETRIC_CONFIG['KEY_SIZE'] // 8
        self.assertEqual(len(key), expected_len)
        print(f"   ✓ Clave generada de {len(key)} bytes.")

    def test_encrypt_decrypt_roundtrip(self):
        """Test: Cifrar y descifrar datos con éxito (ida y vuelta)."""
        print("\n[TEST] Cifrado y descifrado (ida y vuelta)")
        key = self.encryptor.generate_key()
        
        encrypted_data = self.encryptor.encrypt(self.original_data, key)
        self.assertNotEqual(self.original_data, encrypted_data)
        
        decrypted_data = self.encryptor.decrypt(encrypted_data, key)
        self.assertEqual(self.original_data, decrypted_data)
        print("   ✓ Los datos descifrados coinciden con los originales.")

    def test_decrypt_with_wrong_key(self):
        """Test: El descifrado debe fallar si la clave es incorrecta."""
        print("\n[TEST] Descifrado con clave incorrecta")
        key_a = self.encryptor.generate_key()
        key_b = self.encryptor.generate_key()

        encrypted_data = self.encryptor.encrypt(self.original_data, key_a)
        
        # Intentar descifrar con la clave incorrecta (key_b)
        with self.assertRaises(ValueError):
            self.encryptor.decrypt(encrypted_data, key_b)
        print("   ✓ El descifrado falló como se esperaba (ValueError).")

    def test_decrypt_tampered_data(self):
        """Test: El descifrado debe fallar si los datos cifrados son modificados."""
        print("\n[TEST] Descifrado de datos manipulados")
        key = self.encryptor.generate_key()
        encrypted_data = self.encryptor.encrypt(self.original_data, key)
        
        # Manipulamos el último byte del texto cifrado
        tampered_data = encrypted_data[:-1] + bytes([encrypted_data[-1] ^ 1])
        
        with self.assertRaises(ValueError):
            self.encryptor.decrypt(tampered_data, key)
        print("   ✓ El descifrado falló por error de integridad (tag inválido).")

if __name__ == '__main__':
    unittest.main(verbosity=2)