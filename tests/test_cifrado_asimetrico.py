import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.cifrado_asimetrico import AsymmetricEncryptor
from config import ASYMMETRIC_CONFIG
from cryptography.hazmat.primitives.asymmetric import rsa

class TestAsymmetricEncryptor(unittest.TestCase):
    """Tests para la clase AsymmetricEncryptor."""

    def setUp(self):
        self.encryptor = AsymmetricEncryptor()
        # Generamos un par de claves para cada test
        self.private_key = rsa.generate_private_key(
            public_exponent=ASYMMETRIC_CONFIG['PUBLIC_EXPONENT'],
            key_size=ASYMMETRIC_CONFIG['KEY_SIZE']
        )
        self.public_key = self.private_key.public_key()
        self.data_to_encrypt = b"Esta es una clave simetrica secreta"

    def test_encrypt_decrypt_roundtrip(self):
        """Test: Cifrado con clave pública y descifrado con clave privada."""
        print("\n[TEST] Cifrado y descifrado asimétrico (ida y vuelta)")
        
        encrypted_data = self.encryptor.encrypt(self.data_to_encrypt, self.public_key)
        self.assertNotEqual(self.data_to_encrypt, encrypted_data)
        
        decrypted_data = self.encryptor.decrypt(encrypted_data, self.private_key)
        self.assertEqual(self.data_to_encrypt, decrypted_data)
        print("   ✓ Los datos descifrados coinciden con los originales.")

    def test_decrypt_with_wrong_private_key(self):
        """Test: El descifrado debe fallar si se usa la clave privada incorrecta."""
        print("\n[TEST] Descifrado con clave privada incorrecta")

        # Generar un segundo par de claves completamente diferente
        wrong_private_key = rsa.generate_private_key(
            public_exponent=ASYMMETRIC_CONFIG['PUBLIC_EXPONENT'],
            key_size=ASYMMETRIC_CONFIG['KEY_SIZE']
        )
        
        encrypted_data = self.encryptor.encrypt(self.data_to_encrypt, self.public_key)
        
        with self.assertRaises(ValueError):
            self.encryptor.decrypt(encrypted_data, wrong_private_key)
        print("   ✓ El descifrado falló como se esperaba.")

if __name__ == '__main__':
    unittest.main(verbosity=2)