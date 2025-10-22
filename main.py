"""
SecureSend - Gestor de Documentos Confidenciales
Aplicación principal con interfaz de línea de comandos (Versión Simplificada)
"""

import sys
import logging
from pathlib import Path

# Añadir el directorio app al path para importar los módulos
sys.path.insert(0, str(Path(__file__).parent / 'app'))

from app.auth import AuthManager, UserAlreadyExistsError
from config import LOG_CONFIG

# Configurar logging (se mantiene igual, es una buena práctica y requerido por el enunciado)
def setup_logging():
    """Configura el sistema de logging de la aplicación"""
    log_file = LOG_CONFIG['LOG_FILE']
    formatter = logging.Formatter(
        LOG_CONFIG['LOG_FORMAT'],
        datefmt=LOG_CONFIG['DATE_FORMAT']
    )
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    logging.info("=" * 60)
    logging.info("SecureSend - Aplicación iniciada")
    logging.info("=" * 60)


class SecureSendApp:
    """Clase principal de la aplicación SecureSend"""

    def __init__(self):
        """Inicializa la aplicación"""
        self.auth_manager = AuthManager()
        self.current_user = None
        self.logger = logging.getLogger(__name__)

    def show_banner(self):
        """Muestra el banner de la aplicación"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              SECURESEND - Documentos Seguros              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)

    def show_main_menu(self):
        """Muestra el menú principal"""
        print("\n" + "=" * 50)
        print("MENÚ PRINCIPAL")
        print("=" * 50)
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Listar usuarios registrados")
        print("0. Salir")
        print("=" * 50)

    def show_user_menu(self):
        """Muestra el menú de usuario autenticado"""
        print("\n" + "=" * 50)
        # SE HA SIMPLIFICADO: Ya no se muestra el rol.
        print(f"SESIÓN ACTIVA: {self.current_user['username']}")
        print("=" * 50)
        print("1. Ver mi información")
        print("2. Subir documento (próximamente)")
        print("3. Ver mis documentos (próximamente)")
        print("4. Compartir documento (próximamente)")
        print("5. Generar par de claves (próximamente)")
        print("6. Solicitar certificado (próximamente)")
        print("0. Cerrar sesión")
        print("=" * 50)

    def register_user(self):
        """Maneja el registro de un nuevo usuario"""
        print("\n" + "-" * 50)
        print("REGISTRO DE NUEVO USUARIO")
        print("-" * 50)

        try:
            username = input("Nombre de usuario: ").strip()
            if not username:
                print("❌ El nombre de usuario no puede estar vacío")
                return

            email = input("Email: ").strip()
            if not email or '@' not in email:
                print("❌ Email inválido")
                return

            # SE HA ELIMINADO: La sección para elegir el rol de usuario ya no es necesaria.

            print("\nRequisitos de contraseña:")
            print("  - Mínimo 8 caracteres, con mayúsculas, minúsculas y números.")
            password = input("\nContraseña: ").strip()
            password_confirm = input("Confirmar contraseña: ").strip()

            if password != password_confirm:
                print("❌ Las contraseñas no coinciden")
                return

            # SE HA MODIFICADO: La llamada a register_user ya no incluye el rol.
            # (Deberás asegurarte de que tu clase AuthManager también se simplifique).
            user_info = self.auth_manager.register_user(
                username=username,
                password=password,
                email=email
            )

            print("\n" + "=" * 50)
            print("✅ USUARIO REGISTRADO EXITOSAMENTE")
            print("=" * 50)
            print(f"Usuario: {user_info['username']}")
            print(f"Email: {user_info['email']}")
            # SE HA ELIMINADO: La línea que mostraba el rol.
            print(f"Fecha de registro: {user_info['created_at']}")
            print("=" * 50)

            self.logger.info(f"Nuevo usuario registrado desde UI: {username}")

        except UserAlreadyExistsError as e:
            print(f"\n❌ Error: {e}")
        except ValueError as e:
            print(f"\n❌ Error: {e}")
        except Exception as e:
            print(f"\n❌ Error inesperado: {e}")
            self.logger.error(f"Error en registro: {e}", exc_info=True)

    def login_user(self):
        """Maneja el inicio de sesión"""
        print("\n" + "-" * 50)
        print("INICIO DE SESIÓN")
        print("-" * 50)

        username = input("Usuario: ").strip()
        password = input("Contraseña: ").strip()

        if self.auth_manager.authenticate_user(username, password):
            self.current_user = self.auth_manager.get_user_info(username)

            print("\n" + "=" * 50)
            print("✅ AUTENTICACIÓN EXITOSA")
            print("=" * 50)
            print(f"Bienvenido/a, {self.current_user['username']}")
            # SE HA ELIMINADO: La línea que mostraba el rol.
            if self.current_user.get('last_login'):
                print(f"Último acceso: {self.current_user['last_login']}")
            print("=" * 50)

            self.logger.info(f"Login exitoso: {username}")
            return True
        else:
            print("\n❌ Usuario o contraseña incorrectos")
            self.logger.warning(f"Intento de login fallido: {username}")
            return False

    def show_user_info(self):
        """Muestra información del usuario actual"""
        if not self.current_user:
            return

        print("\n" + "=" * 50)
        print("INFORMACIÓN DE USUARIO")
        print("=" * 50)
        print(f"Usuario: {self.current_user['username']}")
        print(f"Email: {self.current_user['email']}")
        # SE HA ELIMINADO: La línea que mostraba el rol.
        print(f"Fecha de registro: {self.current_user['created_at']}")
        if self.current_user.get('last_login'):
            print(f"Último acceso: {self.current_user['last_login']}")
        print(f"Par de claves generado: {'Sí' if self.current_user.get('has_keypair') else 'No'}")
        print(f"Certificado emitido: {'Sí' if self.current_user.get('certificate_issued') else 'No'}")
        print("=" * 50)

    def list_users(self):
        """Lista todos los usuarios registrados"""
        users = self.auth_manager.list_users()
        print("\n" + "=" * 50)
        print(f"USUARIOS REGISTRADOS ({len(users)})")
        print("=" * 50)

        if not users:
            print("No hay usuarios registrados")
        else:
            for user in users:
                print(f"\n  Usuario: {user['username']}")
                print(f"  Email: {user['email']}")
                # SE HA ELIMINADO: La línea que mostraba el rol.
                print(f"  Certificado: {'✓' if user.get('certificate_issued') else '✗'}")
                print("  " + "-" * 40)
        print("=" * 50)

    def user_session(self):
        """Maneja la sesión de un usuario autenticado"""
        while True:
            self.show_user_menu()
            choice = input("\nSeleccione una opción: ").strip()

            if choice == "1":
                self.show_user_info()
            elif choice in ["2", "3", "4", "5", "6"]:
                print("\n⚠️  Funcionalidad en desarrollo")
            elif choice == "0":
                print(f"\n👋 Hasta luego, {self.current_user['username']}")
                self.logger.info(f"Usuario cerró sesión: {self.current_user['username']}")
                self.current_user = None
                break
            else:
                print("\n❌ Opción inválida")

            input("\nPresione Enter para continuar...")

    def run(self):
        """Ejecuta el bucle principal de la aplicación"""
        self.show_banner()
        while True:
            if self.current_user:
                self.user_session()
            else:
                self.show_main_menu()
                choice = input("\nSeleccione una opción: ").strip()

                if choice == "1":
                    self.register_user()
                elif choice == "2":
                    self.login_user()
                elif choice == "3":
                    self.list_users()
                elif choice == "0":
                    print("\n👋 Gracias por usar SecureSend")
                    self.logger.info("Aplicación cerrada por el usuario")
                    break
                else:
                    print("\n❌ Opción inválida")

                if not self.current_user:
                    input("\nPresione Enter para continuar...")


def main():
    """Punto de entrada principal de la aplicación"""
    try:
        setup_logging()
        app = SecureSendApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Aplicación interrumpida por el usuario")
        logging.info("Aplicación interrumpida (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        logging.error(f"Error fatal en aplicación: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()