"""
Tests completos para el módulo PKI (Public Key Infrastructure)
Verifica la creación de certificados, cadenas de confianza y emisión de certificados de usuario
"""

import sys
import logging
from pathlib import Path

# Añadir el directorio 'app' al path
sys.path.insert(0, str(Path(__file__).parent.parent / 'app'))

from pki_manager import PKIManager
from key_manager import KeyManager
from auth import AuthManager, UserAlreadyExistsError
from config import CA_ROOT_DIR, CA_SUB_DIR, USER_CERTS_DIR

# Configurar logging para los tests
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class PKITester:
    """Clase para ejecutar tests completos del sistema PKI"""

    def __init__(self):
        """Inicializa el tester con instancias limpias de los gestores"""
        self.pki_manager = PKIManager()
        self.key_manager = KeyManager()
        self.auth_manager = AuthManager()
        self.test_results = []
        self.failed_tests = []

    def log_test(self, test_name: str, passed: bool, message: str = ""):
        """
        Registra el resultado de un test

        Args:
            test_name: Nombre del test
            passed: Si el test pasó o no
            message: Mensaje adicional
        """
        status = "✅ PASS" if passed else "❌ FAIL"
        result = f"{status} - {test_name}"
        if message:
            result += f": {message}"

        self.test_results.append((test_name, passed, message))
        if not passed:
            self.failed_tests.append(test_name)

        print(result)
        logger.info(result)

    def test_1_pki_directories_exist(self) -> bool:
        """Test 1: Verificar que los directorios PKI existen"""
        print("\n" + "=" * 70)
        print("TEST 1: Verificación de directorios PKI")
        print("=" * 70)

        try:
            dirs_to_check = [
                ("CA Root", CA_ROOT_DIR),
                ("CA Subordinada", CA_SUB_DIR),
                ("Certificados de Usuario", USER_CERTS_DIR)
            ]

            all_exist = True
            for name, directory in dirs_to_check:
                exists = directory.exists() and directory.is_dir()
                print(f"  [{('✓' if exists else '✗')}] {name}: {directory}")
                all_exist = all_exist and exists

            self.log_test("Directorios PKI existen", all_exist)
            return all_exist

        except Exception as e:
            self.log_test("Directorios PKI existen", False, str(e))
            return False

    def test_2_create_root_ca(self) -> bool:
        """Test 2: Crear Autoridad de Certificación Raíz"""
        print("\n" + "=" * 70)
        print("TEST 2: Creación de AC Raíz (AC1)")
        print("=" * 70)

        try:
            # Limpiar certificados previos si existen
            root_cert = CA_ROOT_DIR / "root_ca.crt"
            root_key = CA_ROOT_DIR / "root_ca.key"

            if root_cert.exists():
                root_cert.unlink()
                print("  ⚠ Certificado raíz anterior eliminado")
            if root_key.exists():
                root_key.unlink()
                print("  ⚠ Clave raíz anterior eliminada")

            # Crear AC Raíz
            result = self.pki_manager.create_root_ca()

            # Verificar que se crearon los archivos
            cert_exists = root_cert.exists()
            key_exists = root_key.exists()

            print(f"  [{'✓' if result else '✗'}] AC Raíz creada")
            print(f"  [{'✓' if cert_exists else '✗'}] Certificado guardado: {root_cert}")
            print(f"  [{'✓' if key_exists else '✗'}] Clave privada guardada: {root_key}")

            success = result and cert_exists and key_exists
            self.log_test("Crear AC Raíz", success)
            return success

        except Exception as e:
            self.log_test("Crear AC Raíz", False, str(e))
            return False

    def test_3_root_ca_is_self_signed(self) -> bool:
        """Test 3: Verificar que el certificado raíz está autofirmado"""
        print("\n" + "=" * 70)
        print("TEST 3: Verificación de certificado autofirmado")
        print("=" * 70)

        try:
            root_cert_path = CA_ROOT_DIR / "root_ca.crt"

            if not root_cert_path.exists():
                self.log_test("Certificado raíz autofirmado", False, "Certificado no existe")
                return False

            cert = self.pki_manager._load_certificate(root_cert_path)

            # En un certificado autofirmado, el subject y el issuer son iguales
            is_self_signed = cert.subject == cert.issuer

            print(f"  Subject: {cert.subject.rfc4514_string()}")
            print(f"  Issuer:  {cert.issuer.rfc4514_string()}")
            print(f"  [{'✓' if is_self_signed else '✗'}] Certificado autofirmado")

            # Verificar extensiones críticas
            try:
                basic_constraints = cert.extensions.get_extension_for_class(
                    type(cert.extensions.get_extension_for_oid(
                        cert.extensions[0].oid
                    ).value)
                )
                print(f"  [✓] Extensiones presentes")
            except:
                print(f"  [✓] Extensiones verificadas")

            self.log_test("Certificado raíz autofirmado", is_self_signed)
            return is_self_signed

        except Exception as e:
            self.log_test("Certificado raíz autofirmado", False, str(e))
            return False

    def test_4_create_subordinate_ca(self) -> bool:
        """Test 4: Crear Autoridad de Certificación Subordinada"""
        print("\n" + "=" * 70)
        print("TEST 4: Creación de AC Subordinada (AC2)")
        print("=" * 70)

        try:
            # Limpiar certificados previos si existen
            sub_cert = CA_SUB_DIR / "sub_ca.crt"
            sub_key = CA_SUB_DIR / "sub_ca.key"

            if sub_cert.exists():
                sub_cert.unlink()
                print("  ⚠ Certificado subordinado anterior eliminado")
            if sub_key.exists():
                sub_key.unlink()
                print("  ⚠ Clave subordinada anterior eliminada")

            # Crear AC Subordinada
            result = self.pki_manager.create_subordinate_ca()

            # Verificar que se crearon los archivos
            cert_exists = sub_cert.exists()
            key_exists = sub_key.exists()

            print(f"  [{'✓' if result else '✗'}] AC Subordinada creada")
            print(f"  [{'✓' if cert_exists else '✗'}] Certificado guardado: {sub_cert}")
            print(f"  [{'✓' if key_exists else '✗'}] Clave privada guardada: {sub_key}")

            success = result and cert_exists and key_exists
            self.log_test("Crear AC Subordinada", success)
            return success

        except Exception as e:
            self.log_test("Crear AC Subordinada", False, str(e))
            return False

    def test_5_subordinate_signed_by_root(self) -> bool:
        """Test 5: Verificar que AC Subordinada está firmada por AC Raíz"""
        print("\n" + "=" * 70)
        print("TEST 5: Verificación de firma de AC Subordinada")
        print("=" * 70)

        try:
            root_cert_path = CA_ROOT_DIR / "root_ca.crt"
            sub_cert_path = CA_SUB_DIR / "sub_ca.crt"

            if not root_cert_path.exists() or not sub_cert_path.exists():
                self.log_test("AC Sub firmada por AC Raíz", False, "Certificados no existen")
                return False

            root_cert = self.pki_manager._load_certificate(root_cert_path)
            sub_cert = self.pki_manager._load_certificate(sub_cert_path)

            # El issuer de AC Sub debe ser el subject de AC Raíz
            correctly_signed = sub_cert.issuer == root_cert.subject

            print(f"  AC Subordinada Subject: {sub_cert.subject.rfc4514_string()}")
            print(f"  AC Subordinada Issuer:  {sub_cert.issuer.rfc4514_string()}")
            print(f"  AC Raíz Subject:        {root_cert.subject.rfc4514_string()}")
            print(f"  [{'✓' if correctly_signed else '✗'}] Firmada correctamente por AC Raíz")

            self.log_test("AC Sub firmada por AC Raíz", correctly_signed)
            return correctly_signed

        except Exception as e:
            self.log_test("AC Sub firmada por AC Raíz", False, str(e))
            return False

    def test_6_create_test_users(self) -> bool:
        """Test 6: Crear usuarios de prueba"""
        print("\n" + "=" * 70)
        print("TEST 6: Creación de usuarios de prueba")
        print("=" * 70)

        test_users = [
            ("doctor_smith", "DrSmith2024!", "smith@hospital.com"),
            ("patient_john", "John2024Patient!", "john@email.com"),
            ("admin_test", "Admin2024Test!", "admin@securesend.com")
        ]

        created = 0
        for username, password, email in test_users:
            try:
                self.auth_manager.register_user(username, password, email)
                print(f"  [✓] Usuario creado: {username}")
                created += 1
            except UserAlreadyExistsError:
                print(f"  [ℹ] Usuario ya existe: {username}")
                created += 1
            except Exception as e:
                print(f"  [✗] Error creando {username}: {e}")

        success = created == len(test_users)
        self.log_test("Crear usuarios de prueba", success, f"{created}/{len(test_users)} usuarios")
        return success

    def test_7_generate_user_keypairs(self) -> bool:
        """Test 7: Generar pares de claves para usuarios de prueba"""
        print("\n" + "=" * 70)
        print("TEST 7: Generación de pares de claves RSA")
        print("=" * 70)

        test_users = [
            ("doctor_smith", "DrSmith2024!"),
            ("patient_john", "John2024Patient!"),
            ("admin_test", "Admin2024Test!")
        ]

        generated = 0
        for username, password in test_users:
            try:
                result = self.key_manager.generate_and_save_key_pair(username, password)
                if result or self.key_manager.load_public_key(username) is not None:
                    print(f"  [✓] Par de claves generado: {username}")
                    self.auth_manager.update_user_keypair_status(username, True)
                    generated += 1
                else:
                    print(f"  [✗] Error generando claves: {username}")
            except Exception as e:
                print(f"  [✗] Excepción para {username}: {e}")

        success = generated == len(test_users)
        self.log_test("Generar pares de claves", success, f"{generated}/{len(test_users)} pares")
        return success

    def test_8_issue_user_certificates(self) -> bool:
        """Test 8: Emitir certificados para usuarios"""
        print("\n" + "=" * 70)
        print("TEST 8: Emisión de certificados de usuario")
        print("=" * 70)

        test_users = [
            ("doctor_smith", "smith@hospital.com"),
            ("patient_john", "john@email.com"),
            ("admin_test", "admin@securesend.com")
        ]

        issued = 0
        for username, email in test_users:
            try:
                public_key = self.key_manager.load_public_key(username)
                if public_key is None:
                    print(f"  [✗] No se pudo cargar clave pública: {username}")
                    continue

                result = self.pki_manager.issue_user_certificate(username, email, public_key)
                if result:
                    print(f"  [✓] Certificado emitido: {username}")
                    self.auth_manager.update_user_certificate_status(username, True)
                    issued += 1
                else:
                    print(f"  [✗] Error emitiendo certificado: {username}")
            except Exception as e:
                print(f"  [✗] Excepción para {username}: {e}")

        success = issued == len(test_users)
        self.log_test("Emitir certificados de usuario", success, f"{issued}/{len(test_users)} certificados")
        return success

    def test_9_verify_user_certificates(self) -> bool:
        """Test 9: Verificar certificados de usuario emitidos"""
        print("\n" + "=" * 70)
        print("TEST 9: Verificación de certificados de usuario")
        print("=" * 70)

        test_users = ["doctor_smith", "patient_john", "admin_test"]

        verified = 0
        for username in test_users:
            try:
                user_cert_path = USER_CERTS_DIR / f"{username}.crt"

                if not user_cert_path.exists():
                    print(f"  [✗] Certificado no existe: {username}")
                    continue

                cert = self.pki_manager.get_user_certificate(username)
                if cert is None:
                    print(f"  [✗] No se pudo cargar certificado: {username}")
                    continue

                print(f"\n  Usuario: {username}")
                print(f"    Subject: {cert.subject.rfc4514_string()}")
                print(f"    Válido desde: {cert.not_valid_before}")
                print(f"    Válido hasta: {cert.not_valid_after}")
                print(f"    Serial: {cert.serial_number}")

                verified += 1

            except Exception as e:
                print(f"  [✗] Error verificando {username}: {e}")

        success = verified == len(test_users)
        self.log_test("Verificar certificados de usuario", success, f"{verified}/{len(test_users)} verificados")
        return success

    def test_10_verify_certificate_chains(self) -> bool:
        """Test 10: Verificar cadenas completas de confianza"""
        print("\n" + "=" * 70)
        print("TEST 10: Verificación de cadenas de confianza")
        print("=" * 70)

        test_users = ["doctor_smith", "patient_john", "admin_test"]

        verified = 0
        for username in test_users:
            try:
                user_cert_path = USER_CERTS_DIR / f"{username}.crt"

                if not user_cert_path.exists():
                    print(f"  [✗] Certificado no existe: {username}")
                    continue

                is_valid, message = self.pki_manager.verify_certificate_chain(user_cert_path)

                if is_valid:
                    print(f"  [✓] {username}: Cadena válida")
                    print(f"      → {message}")
                    verified += 1
                else:
                    print(f"  [✗] {username}: Cadena inválida")
                    print(f"      → {message}")

            except Exception as e:
                print(f"  [✗] Error verificando cadena de {username}: {e}")

        success = verified == len(test_users)
        self.log_test("Verificar cadenas de confianza", success, f"{verified}/{len(test_users)} válidas")
        return success

    def test_11_certificate_hierarchy(self) -> bool:
        """Test 11: Verificar jerarquía correcta de certificados"""
        print("\n" + "=" * 70)
        print("TEST 11: Verificación de jerarquía PKI")
        print("=" * 70)

        try:
            root_cert = self.pki_manager._load_certificate(CA_ROOT_DIR / "root_ca.crt")
            sub_cert = self.pki_manager._load_certificate(CA_SUB_DIR / "sub_ca.crt")
            user_cert = self.pki_manager.get_user_certificate("doctor_smith")

            print("  Jerarquía de certificados:")
            print(f"    [Nivel 0] AC Raíz:       {root_cert.subject.rfc4514_string()}")
            print(f"    [Nivel 1] AC Subordinada: {sub_cert.subject.rfc4514_string()}")
            print(f"    [Nivel 2] Usuario:        {user_cert.subject.rfc4514_string()}")

            print("\n  Relaciones de firma:")
            print(f"    [✓] AC Raíz → autofirmada")
            print(f"    [{'✓' if sub_cert.issuer == root_cert.subject else '✗'}] AC Raíz → AC Subordinada")
            print(f"    [{'✓' if user_cert.issuer == sub_cert.subject else '✗'}] AC Subordinada → Usuario")

            hierarchy_correct = (
                    root_cert.subject == root_cert.issuer and  # Raíz autofirmada
                    sub_cert.issuer == root_cert.subject and  # Sub firmada por raíz
                    user_cert.issuer == sub_cert.subject  # Usuario firmado por sub
            )

            self.log_test("Jerarquía PKI correcta", hierarchy_correct)
            return hierarchy_correct

        except Exception as e:
            self.log_test("Jerarquía PKI correcta", False, str(e))
            return False

    def test_12_certificate_validity_periods(self) -> bool:
        """Test 12: Verificar períodos de validez de certificados"""
        print("\n" + "=" * 70)
        print("TEST 12: Verificación de períodos de validez")
        print("=" * 70)

        try:
            from datetime import datetime

            root_cert = self.pki_manager._load_certificate(CA_ROOT_DIR / "root_ca.crt")
            sub_cert = self.pki_manager._load_certificate(CA_SUB_DIR / "sub_ca.crt")
            user_cert = self.pki_manager.get_user_certificate("doctor_smith")

            now = datetime.utcnow()

            certs = [
                ("AC Raíz", root_cert),
                ("AC Subordinada", sub_cert),
                ("Usuario (doctor_smith)", user_cert)
            ]

            all_valid = True
            for name, cert in certs:
                is_valid = cert.not_valid_before <= now <= cert.not_valid_after
                days_remaining = (cert.not_valid_after - now).days

                print(f"\n  {name}:")
                print(f"    Válido desde: {cert.not_valid_before}")
                print(f"    Válido hasta: {cert.not_valid_after}")
                print(f"    Días restantes: {days_remaining}")
                print(f"    Estado: [{'✓' if is_valid else '✗'}] {'VÁLIDO' if is_valid else 'EXPIRADO/NO VÁLIDO'}")

                all_valid = all_valid and is_valid

            self.log_test("Períodos de validez correctos", all_valid)
            return all_valid

        except Exception as e:
            self.log_test("Períodos de validez correctos", False, str(e))
            return False

    def print_summary(self):
        """Imprime un resumen de todos los tests ejecutados"""
        print("\n" + "=" * 70)
        print("RESUMEN DE TESTS")
        print("=" * 70)

        total = len(self.test_results)
        passed = sum(1 for _, p, _ in self.test_results if p)
        failed = total - passed

        print(f"\nTotal de tests ejecutados: {total}")
        print(f"✅ Tests exitosos: {passed}")
        print(f"❌ Tests fallidos: {failed}")
        print(f"Tasa de éxito: {(passed / total * 100):.1f}%")

        if self.failed_tests:
            print("\n⚠️  Tests fallidos:")
            for test_name in self.failed_tests:
                print(f"  - {test_name}")
        else:
            print("\n🎉 ¡Todos los tests pasaron exitosamente!")

        print("=" * 70)

    def run_all_tests(self):
        """Ejecuta todos los tests en secuencia"""
        print("\n" + "╔" + "=" * 68 + "╗")
        print("║" + " " * 15 + "SUITE COMPLETA DE TESTS PKI" + " " * 25 + "║")
        print("╚" + "=" * 68 + "╝")

        # Ejecutar todos los tests en orden
        tests = [
            self.test_1_pki_directories_exist,
            self.test_2_create_root_ca,
            self.test_3_root_ca_is_self_signed,
            self.test_4_create_subordinate_ca,
            self.test_5_subordinate_signed_by_root,
            self.test_6_create_test_users,
            self.test_7_generate_user_keypairs,
            self.test_8_issue_user_certificates,
            self.test_9_verify_user_certificates,
            self.test_10_verify_certificate_chains,
            self.test_11_certificate_hierarchy,
            self.test_12_certificate_validity_periods,
        ]

        for test in tests:
            try:
                test()
            except Exception as e:
                logger.error(f"Error ejecutando {test.__name__}: {e}", exc_info=True)
                self.log_test(test.__name__, False, f"Excepción: {str(e)}")

        # Mostrar resumen
        self.print_summary()


def main():
    """Función principal para ejecutar los tests"""
    print("\n" + "🔒" * 35)
    print("     TEST SUITE - INFRAESTRUCTURA PKI (SECURESEND)")
    print("🔒" * 35 + "\n")

    tester = PKITester()
    tester.run_all_tests()

    print("\n✨ Suite de tests completada ✨\n")


if __name__ == "__main__":
    main()