"""
SecureSend - Gestor de Documentos Confidenciales
Aplicación principal con interfaz de línea de comandos.
Este fichero orquesta las llamadas a los diferentes módulos de la aplicación.
"""

import sys
import logging
import getpass  # Para solicitar contraseñas de forma segura sin mostrarlas en pantalla
import json
from pathlib import Path

# Añadir el directorio 'app' al path para poder importar los módulos
# Esto permite que el script se ejecute desde la raíz del proyecto.
sys.path.insert(0, str(Path(__file__).parent / 'app'))

# Importamos todas las clases "expertas" desde sus respectivos módulos
from auth import AuthManager, UserAlreadyExistsError
from key_manager import KeyManager
from cifrado_simetrico import SymmetricEncryptor   # Importado desde tu nuevo nombre de fichero
from cifrado_asimetrico import AsymmetricEncryptor # Importado desde tu nuevo nombre de fichero
from hmac_auth import HmacManager
from config import LOG_CONFIG, DOCUMENTS_DIR

#Configuración del Logging
def setup_logging():
    """Configura el sistema de logging para guardar eventos en un fichero y mostrarlos en consola."""
    log_file = LOG_CONFIG['LOG_FILE']
    formatter = logging.Formatter(
        LOG_CONFIG['LOG_FORMAT'],
        datefmt=LOG_CONFIG['DATE_FORMAT']
    )
    
    # Handler para el fichero
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)  # Guarda todo, desde DEBUG hacia arriba

    # Handler para la consola
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO) # Muestra en consola solo INFO y más importantes

    # Configurar el logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logging.info("=" * 60)
    logging.info("SecureSend - Aplicación iniciada")
    logging.info("=" * 60)


class SecureSendApp:
    """Clase principal que encapsula toda la lógica de la aplicación."""

    def __init__(self):
        """Inicializa la aplicación creando instancias de todos los gestores necesarios."""
        self.auth_manager = AuthManager()
        self.key_manager = KeyManager()
        self.sym_encryptor = SymmetricEncryptor()
        self.asym_encryptor = AsymmetricEncryptor()
        self.hmac_manager = HmacManager()
        self.current_user = None
        self.logger = logging.getLogger(__name__)

    # Métodos de la Interfaz de Usuario (UI)

    def show_banner(self):
        """Muestra el banner de bienvenida de la aplicación."""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              SECURESEND - Documentos Seguros              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def show_main_menu(self):
        """Muestra el menú principal para usuarios no autenticados."""
        print("\n" + "=" * 50)
        print("MENÚ PRINCIPAL")
        print("=" * 50)
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Listar usuarios registrados")
        print("0. Salir")
        print("=" * 50)

    def show_user_menu(self):
        """Muestra el menú de acciones para un usuario que ha iniciado sesión."""
        print("\n" + "=" * 50)
        print(f"SESIÓN ACTIVA: {self.current_user['username']}")
        print("=" * 50)
        print("1. Ver mi información")
        
        # Menú dinámico: si el usuario no tiene claves, la opción es generarlas.
        # Si ya las tiene, la opción es subir un documento.
        has_keys = self.current_user.get('has_keypair', False)
        if not has_keys:
            print("2. Generar mi par de claves (¡Primer paso requerido!)")
        else:
            print("2. Subir documento seguro")
            print("3. Ver mis documentos (próximamente)")
        
        print("0. Cerrar sesión")
        print("=" * 50)

    # Métodos de Lógica de la Aplicación

    def register_user(self):
        """Gestiona el flujo de registro de un nuevo usuario."""
        print("\n" + "-" * 50)
        print("REGISTRO DE NUEVO USUARIO")
        print("-" * 50)
        try:
            username = input("Nombre de usuario: ").strip()
            email = input("Email: ").strip()
            print("\nRequisitos: Mínimo 8 caracteres, con mayúsculas, minúsculas y números.")
            password = getpass.getpass("Contraseña: ")
            password_confirm = getpass.getpass("Confirmar contraseña: ")

            if password != password_confirm:
                print("\n❌ Las contraseñas no coinciden.")
                return

            user_info = self.auth_manager.register_user(username=username, password=password, email=email)
            print("\n✅ ¡Usuario registrado exitosamente! Ahora puedes iniciar sesión.")
            self.logger.info(f"Nuevo usuario registrado desde UI: {username}")
        except (UserAlreadyExistsError, ValueError) as e:
            print(f"\n❌ Error de registro: {e}")
        except Exception as e:
            print(f"\n❌ Error inesperado durante el registro: {e}")
            self.logger.error(f"Error en registro: {e}", exc_info=True)

    def login_user(self):
        """Gestiona el flujo de inicio de sesión."""
        print("\n" + "-" * 50)
        print("INICIO DE SESIÓN")
        print("-" * 50)
        username = input("Usuario: ").strip()
        password = getpass.getpass("Contraseña: ")

        if self.auth_manager.authenticate_user(username, password):
            self.current_user = self.auth_manager.get_user_info(username)
            print(f"\n✅ Autenticación exitosa. ¡Bienvenido/a, {username}!")
            self.logger.info(f"Login exitoso: {username}")
        else:
            print("\n❌ Usuario o contraseña incorrectos.")
            self.logger.warning(f"Intento de login fallido para el usuario: {username}")
            
    def list_users(self):
        """Muestra una lista de todos los usuarios registrados."""
        users = self.auth_manager.list_users()
        print("\n" + "=" * 50)
        print(f"USUARIOS REGISTRADOS ({len(users)})")
        print("=" * 50)
        if not users:
            print("No hay usuarios registrados.")
        else:
            for user in users:
                print(f"  - {user['username']} ({user['email']})")
        print("=" * 50)

    def show_user_info(self):
        """Muestra la información detallada del usuario actual."""
        if not self.current_user: return
        # Se recarga la info por si ha cambiado (ej. se han generado las claves)
        self.current_user = self.auth_manager.get_user_info(self.current_user['username'])
        print("\n" + "=" * 50)
        print("INFORMACIÓN DE USUARIO")
        print("=" * 50)
        for key, value in self.current_user.items():
            print(f"  {key.replace('_', ' ').capitalize()}: {value}")
        print("=" * 50)

    def generate_user_keys(self):
        """Orquesta la generación del par de claves RSA para el usuario."""
        username = self.current_user['username']
        print("\n" + "-" * 50)
        print("GENERACIÓN DE PAR DE CLAVES ASIMÉTRICAS (RSA)")
        print("-" * 50)
        print("Tu clave privada será cifrada con tu contraseña de inicio de sesión.")
        
        password = getpass.getpass("Introduce tu contraseña para confirmar: ")
        if not self.auth_manager.authenticate_user(username, password):
            print("\n❌ Contraseña incorrecta. Abortando.")
            return

        if self.key_manager.generate_and_save_key_pair(username, password):
            self.auth_manager.update_user_keypair_status(username, True)
            self.current_user['has_keypair'] = True # Actualizar estado en la sesión actual
            print("\n✅ ¡Par de claves generado y guardado de forma segura!")
        else:
            print("\n❌ Error al generar las claves. Puede que ya existan.")

    def upload_document(self):
        """Gestiona el flujo completo de subir y asegurar un documento."""
        username = self.current_user['username']
        print("\n" + "-" * 50)
        print("SUBIR DOCUMENTO SEGURO")
        print("-" * 50)
        file_path_str = input("Ruta completa del fichero a subir: ").strip()
        file_path = Path(file_path_str)

        if not file_path.exists() or not file_path.is_file():
            print(f"❌ Error: El fichero '{file_path_str}' no existe.")
            return
        
        original_data = file_path.read_bytes()
        print("\nIniciando proceso de cifrado y autenticación...")
        
        # SECUENCIA CRIPTOGRÁFICA 
        
        # Paso 1: Generar una clave simétrica única para este documento.
        sym_key = self.sym_encryptor.generate_key()
        
        # Paso 2: Cifrar el documento con la clave simétrica (AES-GCM).
        encrypted_document = self.sym_encryptor.encrypt(original_data, sym_key)
        
        # Paso 3: Cargar la clave PÚBLICA del usuario.
        public_key = self.key_manager.load_public_key(username)
        if not public_key:
            print("❌ Error crítico: No se pudo cargar tu clave pública.")
            return
            
        # Paso 4: Cifrar la clave simétrica con la clave pública del usuario (RSA).
        encrypted_sym_key = self.asym_encryptor.encrypt(sym_key, public_key)
        
        # Paso 5: Generar una clave HMAC única para este documento.
        hmac_key = self.hmac_manager.generate_key()
        
        # Paso 6: Generar un HMAC del documento CIFRADO.
        hmac_tag = self.hmac_manager.generate_hmac(encrypted_document, hmac_key)
        
        # Paso 7: Cifrar la clave HMAC también con la clave pública del usuario.
        encrypted_hmac_key = self.asym_encryptor.encrypt(hmac_key, public_key)

        # ALMACENAMIENTO
        
        user_docs_dir = DOCUMENTS_DIR / username
        user_docs_dir.mkdir(exist_ok=True)
        
        # Guardar el fichero cifrado
        encrypted_file_path = user_docs_dir / f"{file_path.name}.enc"
        encrypted_file_path.write_bytes(encrypted_document)

        # Crear un fichero de metadatos con las claves cifradas y el HMAC
        metadata = {
            'encrypted_sym_key_hex': encrypted_sym_key.hex(),
            'encrypted_hmac_key_hex': encrypted_hmac_key.hex(),
            'hmac_tag': hmac_tag,
        }
        meta_file_path = user_docs_dir / f"{file_path.name}.meta"
        with open(meta_file_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        print("\n✅ DOCUMENTO SUBIDO Y ASEGURADO CORRECTAMENTE")
        print(f"   - Fichero cifrado: {encrypted_file_path.name}")
        print(f"   - Metadatos: {meta_file_path.name}")
        self.logger.info(f"Usuario {username} subió el documento {file_path.name} de forma segura.")

    # Bucles Principales de la Aplicación 

    def user_session(self):
        """Bucle principal para un usuario autenticado."""
        while True:
            self.current_user = self.auth_manager.get_user_info(self.current_user['username'])
            self.show_user_menu()
            choice = input("\nSeleccione una opción: ").strip()

            if choice == "1": self.show_user_info()
            elif choice == "2":
                if not self.current_user.get('has_keypair'): self.generate_user_keys()
                else: self.upload_document()
            elif choice == "3": print("\n⚠️  Funcionalidad en desarrollo.")
            elif choice == "0":
                print(f"\n👋 Sesión cerrada. ¡Hasta luego, {self.current_user['username']}!")
                self.logger.info(f"Usuario cerró sesión: {self.current_user['username']}")
                self.current_user = None
                break
            else: print("\n❌ Opción inválida.")
            input("\nPresione Enter para continuar...")

    def run(self):
        """Bucle principal de la aplicación."""
        self.show_banner()
        while True:
            if self.current_user:
                self.user_session()
            else:
                self.show_main_menu()
                choice = input("\nSeleccione una opción: ").strip()
                if choice == "1": self.register_user()
                elif choice == "2": self.login_user()
                elif choice == "3": self.list_users()
                elif choice == "0":
                    print("\n👋 Gracias por usar SecureSend.")
                    self.logger.info("Aplicación cerrada por el usuario.")
                    break
                else: print("\n❌ Opción inválida.")
                
                if not self.current_user:
                    input("\nPresione Enter para continuar...")


# Punto de Entrada del Script
def main():
    """Función principal que inicia la aplicación."""
    try:
        setup_logging()
        app = SecureSendApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Aplicación interrumpida por el usuario.")
        logging.info("Aplicación interrumpida (Ctrl+C).")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Ha ocurrido un error fatal: {e}")
        logging.critical(f"Error fatal en la aplicación: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()