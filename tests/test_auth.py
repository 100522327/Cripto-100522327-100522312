"""
Tests unitarios para el módulo de autenticación
Ejecutar con: python -m unittest tests/test_auth.py
"""

import unittest
import sys
import json
import shutil
from pathlib import Path

# Añadir el directorio raíz al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.auth import AuthManager, UserAlreadyExistsError
from config import USERS_DB_FILE, USERS_DIR, AUTH_CONFIG


class TestAuthManager(unittest.TestCase):
    """Tests para la clase AuthManager"""

    @classmethod
    def setUpClass(cls):
        """Se ejecuta una vez antes de todos los tests"""
        print("\n" + "=" * 60)
        print("INICIANDO SUITE DE TESTS DE AUTENTICACIÓN")
        print("=" * 60)

    def setUp(self):
        """
        Se ejecuta antes de cada test.
        Garantiza un entorno limpio y predecible.
        """
        # 1. Borrar cualquier base de datos de un test anterior para empezar de cero.
        #    Esto evita el error de "archivo corrupto" porque AuthManager no encontrará un archivo vacío.
        if USERS_DB_FILE.exists():
            USERS_DB_FILE.unlink()

        # 2. Crear un AuthManager limpio para cada test.
        #    Ahora, _load_users_db() verá que el archivo no existe y creará una DB vacía en memoria.
        self.auth = AuthManager()

    def tearDown(self):
        """
        Se ejecuta después de cada test.
        Limpia los artefactos creados por el test.
        """
        # 1. Borrar la base de datos que el test pudo haber creado.
        if USERS_DB_FILE.exists():
            USERS_DB_FILE.unlink()

        # 2. Limpiar cualquier directorio de usuario creado durante el test.
        #    (Tu lógica original para esto es buena).
        for user_dir in USERS_DIR.iterdir():
            if user_dir.is_dir() and user_dir.name.startswith('test_'):
                shutil.rmtree(user_dir)

    # ========== TESTS DE REGISTRO ==========

    def test_register_user_success(self):
        """Test: Registro exitoso de un usuario"""
        print("\n[TEST] Registro exitoso de usuario")

        user_info = self.auth.register_user(
            username="test_user1",
            password="TestPass123",
            email="test1@example.com",
            role="user"
        )

        self.assertEqual(user_info['username'], "test_user1")
        self.assertEqual(user_info['email'], "test1@example.com")
        self.assertEqual(user_info['role'], "user")
        self.assertIn('created_at', user_info)

        # Verificar que se guardó en la base de datos
        self.assertIn("test_user1", self.auth.users_db)

        print("   ✓ Usuario registrado correctamente")

    def test_register_user_duplicate(self):
        """Test: Intento de registrar usuario duplicado"""
        print("\n[TEST] Registro de usuario duplicado")

        # Registrar primer usuario
        self.auth.register_user(
            username="test_duplicate",
            password="TestPass123",
            email="test@example.com"
        )

        # Intentar registrar el mismo usuario
        with self.assertRaises(UserAlreadyExistsError):
            self.auth.register_user(
                username="test_duplicate",
                password="AnotherPass456",
                email="another@example.com"
            )

        print("   ✓ Excepción UserAlreadyExistsError lanzada correctamente")

    def test_register_weak_password_short(self):
        """Test: Contraseña demasiado corta"""
        print("\n[TEST] Contraseña demasiado corta")

        with self.assertRaises(ValueError) as context:
            self.auth.register_user(
                username="test_weak1",
                password="Short1",  # Solo 6 caracteres
                email="test@example.com"
            )

        self.assertIn("al menos", str(context.exception).lower())
        print(f"   ✓ Error detectado: {context.exception}")

    def test_register_weak_password_no_uppercase(self):
        """Test: Contraseña sin mayúsculas"""
        print("\n[TEST] Contraseña sin mayúsculas")

        with self.assertRaises(ValueError) as context:
            self.auth.register_user(
                username="test_weak2",
                password="testpass123",  # Sin mayúsculas
                email="test@example.com"
            )

        self.assertIn("mayúscula", str(context.exception).lower())
        print(f"   ✓ Error detectado: {context.exception}")

    def test_register_weak_password_no_lowercase(self):
        """Test: Contraseña sin minúsculas"""
        print("\n[TEST] Contraseña sin minúsculas")

        with self.assertRaises(ValueError) as context:
            self.auth.register_user(
                username="test_weak3",
                password="TESTPASS123",  # Sin minúsculas
                email="test@example.com"
            )

        self.assertIn("minúscula", str(context.exception).lower())
        print(f"   ✓ Error detectado: {context.exception}")

    def test_register_weak_password_no_digit(self):
        """Test: Contraseña sin números"""
        print("\n[TEST] Contraseña sin números")

        with self.assertRaises(ValueError) as context:
            self.auth.register_user(
                username="test_weak4",
                password="TestPassword",  # Sin números
                email="test@example.com"
            )

        self.assertIn("número", str(context.exception).lower())
        print(f"   ✓ Error detectado: {context.exception}")

    def test_register_creates_user_directory(self):
        """Test: Se crea el directorio personal del usuario"""
        print("\n[TEST] Creación de directorio de usuario")

        self.auth.register_user(
            username="test_directory",
            password="TestPass123",
            email="test@example.com"
        )

        user_dir = USERS_DIR / "test_directory"
        self.assertTrue(user_dir.exists())
        self.assertTrue(user_dir.is_dir())

        print("   ✓ Directorio de usuario creado correctamente")

    # ========== TESTS DE AUTENTICACIÓN ==========

    def test_authenticate_success(self):
        """Test: Autenticación exitosa"""
        print("\n[TEST] Autenticación exitosa")

        # Registrar usuario
        self.auth.register_user(
            username="test_auth",
            password="TestPass123",
            email="test@example.com"
        )

        # Autenticar con credenciales correctas
        result = self.auth.authenticate_user("test_auth", "TestPass123")
        self.assertTrue(result)

        # Verificar que se actualizó last_login
        user_info = self.auth.get_user_info("test_auth")
        self.assertIsNotNone(user_info['last_login'])

        print("   ✓ Autenticación exitosa y last_login actualizado")

    def test_authenticate_wrong_password(self):
        """Test: Autenticación con contraseña incorrecta"""
        print("\n[TEST] Autenticación con contraseña incorrecta")

        # Registrar usuario
        self.auth.register_user(
            username="test_wrong_pass",
            password="TestPass123",
            email="test@example.com"
        )

        # Intentar autenticar con contraseña incorrecta
        result = self.auth.authenticate_user("test_wrong_pass", "WrongPass456")
        self.assertFalse(result)

        print("   ✓ Autenticación rechazada correctamente")

    def test_authenticate_nonexistent_user(self):
        """Test: Autenticación de usuario inexistente"""
        print("\n[TEST] Autenticación de usuario inexistente")

        result = self.auth.authenticate_user("nonexistent", "SomePass123")
        self.assertFalse(result)

        print("   ✓ Usuario inexistente rechazado correctamente")

    # ========== TESTS DE HASH Y SALT ==========

    def test_unique_salt_per_user(self):
        """Test: Cada usuario tiene un salt único"""
        print("\n[TEST] Unicidad de salts")

        # Registrar dos usuarios con la misma contraseña
        self.auth.register_user("test_salt1", "SamePass123", "test1@example.com")
        self.auth.register_user("test_salt2", "SamePass123", "test2@example.com")

        salt1 = self.auth.users_db["test_salt1"]['salt']
        salt2 = self.auth.users_db["test_salt2"]['salt']

        self.assertNotEqual(salt1, salt2)
        print(f"   ✓ Salts únicos generados")
        print(f"     Salt 1: {salt1[:16]}...")
        print(f"     Salt 2: {salt2[:16]}...")

    def test_different_hash_same_password(self):
        """Test: Mismo password genera diferentes hashes (por diferentes salts)"""
        print("\n[TEST] Hashes diferentes para misma contraseña")

        # Registrar dos usuarios con la misma contraseña
        self.auth.register_user("test_hash1", "SamePass123", "test1@example.com")
        self.auth.register_user("test_hash2", "SamePass123", "test2@example.com")

        hash1 = self.auth.users_db["test_hash1"]['password_hash']
        hash2 = self.auth.users_db["test_hash2"]['password_hash']

        self.assertNotEqual(hash1, hash2)
        print("   ✓ Hashes diferentes generados para la misma contraseña")

    def test_salt_length(self):
        """Test: Longitud del salt según configuración"""
        print("\n[TEST] Longitud del salt")

        self.auth.register_user("test_salt_len", "TestPass123", "test@example.com")

        salt = self.auth.users_db["test_salt_len"]['salt']
        # Salt está en hexadecimal, así que cada byte = 2 caracteres hex
        expected_length = AUTH_CONFIG['SALT_LENGTH'] * 2

        self.assertEqual(len(salt), expected_length)
        print(f"   ✓ Salt tiene {len(salt)} caracteres (esperado: {expected_length})")

    def test_hash_length(self):
        """Test: Longitud del hash según configuración"""
        print("\n[TEST] Longitud del hash")

        self.auth.register_user("test_hash_len", "TestPass123", "test@example.com")

        password_hash = self.auth.users_db["test_hash_len"]['password_hash']
        # Hash está en hexadecimal
        expected_length = AUTH_CONFIG['DERIVED_KEY_LENGTH'] * 2

        self.assertEqual(len(password_hash), expected_length)
        print(f"   ✓ Hash tiene {len(password_hash)} caracteres (esperado: {expected_length})")

    # ========== TESTS DE GESTIÓN DE USUARIOS ==========

    def test_get_user_info(self):
        """Test: Obtener información de usuario"""
        print("\n[TEST] Obtener información de usuario")

        self.auth.register_user(
            username="test_info",
            password="TestPass123",
            email="info@example.com",
            role="professional"
        )

        user_info = self.auth.get_user_info("test_info")

        self.assertIsNotNone(user_info)
        self.assertEqual(user_info['username'], "test_info")
        self.assertEqual(user_info['email'], "info@example.com")
        self.assertEqual(user_info['role'], "professional")

        # Verificar que NO devuelve información sensible
        self.assertNotIn('password_hash', user_info)
        self.assertNotIn('salt', user_info)

        print("   ✓ Información obtenida sin datos sensibles")

    def test_get_user_info_nonexistent(self):
        """Test: Obtener info de usuario inexistente"""
        print("\n[TEST] Info de usuario inexistente")

        user_info = self.auth.get_user_info("nonexistent")
        self.assertIsNone(user_info)

        print("   ✓ Retorna None para usuario inexistente")

    def test_update_keypair_status(self):
        """Test: Actualizar estado de par de claves"""
        print("\n[TEST] Actualizar estado de keypair")

        self.auth.register_user("test_keypair", "TestPass123", "test@example.com")

        # Inicialmente debe ser False
        user_info = self.auth.get_user_info("test_keypair")
        self.assertFalse(user_info['has_keypair'])

        # Actualizar estado
        self.auth.update_user_keypair_status("test_keypair", True)

        # Verificar actualización
        user_info = self.auth.get_user_info("test_keypair")
        self.assertTrue(user_info['has_keypair'])

        print("   ✓ Estado de keypair actualizado correctamente")

    def test_update_certificate_status(self):
        """Test: Actualizar estado de certificado"""
        print("\n[TEST] Actualizar estado de certificado")

        self.auth.register_user("test_cert", "TestPass123", "test@example.com")

        # Inicialmente debe ser False
        user_info = self.auth.get_user_info("test_cert")
        self.assertFalse(user_info['certificate_issued'])

        # Actualizar estado
        self.auth.update_user_certificate_status("test_cert", True)

        # Verificar actualización
        user_info = self.auth.get_user_info("test_cert")
        self.assertTrue(user_info['certificate_issued'])

        print("   ✓ Estado de certificado actualizado correctamente")

    def test_list_users(self):
        """Test: Listar todos los usuarios"""
        print("\n[TEST] Listar usuarios")

        # Registrar varios usuarios
        self.auth.register_user("test_list1", "TestPass123", "test1@example.com")
        self.auth.register_user("test_list2", "TestPass123", "test2@example.com")
        self.auth.register_user("test_list3", "TestPass123", "test3@example.com")

        users = self.auth.list_users()

        self.assertEqual(len(users), 3)

        # Verificar que no contiene información sensible
        for user in users:
            self.assertNotIn('password_hash', user)
            self.assertNotIn('salt', user)

        print(f"   ✓ {len(users)} usuarios listados sin datos sensibles")

    # ========== TESTS DE PERSISTENCIA ==========

    def test_persistence_after_reload(self):
        """Test: Los datos persisten después de recargar"""
        print("\n[TEST] Persistencia de datos")

        # Registrar usuario
        self.auth.register_user("test_persist", "TestPass123", "persist@example.com")

        # Crear nuevo AuthManager (simula reinicio de aplicación)
        new_auth = AuthManager()

        # Verificar que el usuario existe
        self.assertIn("test_persist", new_auth.users_db)

        # Verificar que puede autenticarse
        result = new_auth.authenticate_user("test_persist", "TestPass123")
        self.assertTrue(result)

        print("   ✓ Datos persisten correctamente tras reinicio")

    def test_database_file_format(self):
        """Test: Formato del archivo de base de datos"""
        print("\n[TEST] Formato de base de datos JSON")

        self.auth.register_user("test_format", "TestPass123", "test@example.com")

        # Verificar que el archivo existe y es JSON válido
        self.assertTrue(USERS_DB_FILE.exists())

        with open(USERS_DB_FILE, 'r') as f:
            data = json.load(f)

        self.assertIsInstance(data, dict)
        self.assertIn("test_format", data)

        print("   ✓ Base de datos en formato JSON válido")


class TestPasswordHashing(unittest.TestCase):
    """Tests específicos para funciones de hashing"""

    def setUp(self):
        """Se ejecuta antes de cada test"""
        self.auth = AuthManager()

    def test_pbkdf2_iterations(self):
        """Test: Verificar número de iteraciones PBKDF2"""
        print("\n[TEST] Iteraciones PBKDF2")

        iterations = AUTH_CONFIG['PBKDF2_ITERATIONS']
        self.assertGreaterEqual(iterations, 600000)  # Recomendación OWASP 2023

        print(f"   ✓ Usando {iterations} iteraciones (OWASP recomienda ≥600,000)")

    def test_hash_algorithm(self):
        """Test: Verificar algoritmo de hash"""
        print("\n[TEST] Algoritmo de hash")

        algorithm = AUTH_CONFIG['HASH_ALGORITHM']
        self.assertEqual(algorithm, 'sha256')

        print(f"   ✓ Usando {algorithm.upper()}")


def run_tests():
    """Ejecuta todos los tests y muestra un resumen"""
    # Crear test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Añadir todos los tests
    suite.addTests(loader.loadTestsFromTestCase(TestAuthManager))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordHashing))

    # Ejecutar tests con verbosidad
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Mostrar resumen
    print("\n" + "=" * 60)
    print("RESUMEN DE TESTS")
    print("=" * 60)
    print(f"Tests ejecutados: {result.testsRun}")
    print(f"Tests exitosos: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Fallos: {len(result.failures)}")
    print(f"Errores: {len(result.errors)}")
    print("=" * 60)

    return result.wasSuccessful()


if __name__ == '__main__':
    import sys

    success = run_tests()
    sys.exit(0 if success else 1)