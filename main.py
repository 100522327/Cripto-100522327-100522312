"""
SecureSend - Gestor de Documentos Confidenciales.
Aplicación principal con interfaz de línea de comandos (CLI).
Este fichero actúa como controlador principal, orquestando las llamadas a los 
diferentes módulos de seguridad (autenticación, cifrado, PKI, firmas).
"""

import sys
import logging
import getpass  
import json
from pathlib import Path

# Configuración del path para importar módulos locales
# Añade el directorio 'app' al sys.path para permitir importaciones relativas
sys.path.insert(0, str(Path(__file__).parent / 'app'))

# Importación de módulos de lógica de negocio y criptografía
from auth import AuthManager, UserAlreadyExistsError
from key_manager import KeyManager
from cifrado_simetrico import SymmetricEncryptor
from cifrado_asimetrico import AsymmetricEncryptor
from hmac_auth import HmacManager
from pki_manager import PKIManager
from digital_signature import SignatureManager 
from config import LOG_CONFIG, DOCUMENTS_DIR, USER_CERTS_DIR

def setup_logging():
    """
    Configura el sistema de logging de la aplicación.
    Establece dos salidas:
    1. Archivo de log: Registra todos los eventos (nivel DEBUG).
    2. Consola: Muestra información relevante al usuario (nivel INFO).
    """
    log_file = LOG_CONFIG['LOG_FILE']
    formatter = logging.Formatter(
        LOG_CONFIG['LOG_FORMAT'],
        datefmt=LOG_CONFIG['DATE_FORMAT']
    )

    # Configuración del handler de archivo (rotación y persistencia)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    # Configuración del handler de consola (feedback visual)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    # Configuración del logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logging.info("=" * 60)
    logging.info("SecureSend - Aplicación iniciada")
    logging.info("=" * 60)


class SecureSendApp:
    """
    Clase controladora principal.
    Encapsula el estado de la aplicación (usuario actual) y las instancias
    de los gestores de seguridad.
    """

    def __init__(self):
        """
        Constructor de la aplicación.
        Inicializa todas las instancias de los gestores criptográficos.
        """
        # Inicialización de gestores de lógica de negocio
        self.auth_manager = AuthManager()
        self.key_manager = KeyManager()
        
        # Inicialización de motores criptográficos
        self.sym_encryptor = SymmetricEncryptor()      # AES-GCM
        self.asym_encryptor = AsymmetricEncryptor()    # RSA-OAEP
        self.hmac_manager = HmacManager()              # HMAC-SHA256
        self.pki_manager = PKIManager()                # Gestión de Certificados X.509
        self.signature_manager = SignatureManager()    # Firmas Digitales RSA-PSS
        
        self.current_user = None
        self.logger = logging.getLogger(__name__)

        # Verificación e inicialización automática de la PKI al arranque
        self._initialize_pki()

    def _initialize_pki(self):
        """
        Verifica la existencia de la infraestructura de clave pública (PKI).
        Si no existe, crea la Autoridad de Certificación Raíz y la Subordinada.
        """
        if not self.pki_manager.pki_exists():
            self.logger.info("Infraestructura PKI no detectada. Iniciando despliegue...")
            print("\n" + "=" * 60)
            print("INICIALIZACIÓN DE PKI")
            print("=" * 60)
            print("Desplegando jerarquía de confianza...")

            # Contraseñas para las CAs
            ROOT_CA_PASSWORD = "RootCa"
            SUB_CA_PASSWORD = "SubCa"

            # Crear AC Raíz con contraseña
            if self.pki_manager.create_root_ca(password=ROOT_CA_PASSWORD):
                print("✅ Autoridad de Certificación Raíz (AC1) creada")

            # Crear AC Subordinada con contraseña
            if self.pki_manager.create_subordinate_ca(
                    root_ca_password=ROOT_CA_PASSWORD,
                    sub_ca_password=SUB_CA_PASSWORD
            ):
                print("✅ Autoridad de Certificación Subordinada (AC2) creada")

            print("=" * 60)
        else:
            self.logger.info("Infraestructura PKI cargada correctamente.")

    # -------------------------------------------------------------------------
    # Métodos de la Interfaz de Usuario (UI) - Vistas
    # -------------------------------------------------------------------------

    def show_banner(self):
        """Renderiza el banner ASCII de bienvenida."""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              SECURESEND - Documentos Seguros              ║
║                      con PKI Integrada                    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)

    def show_main_menu(self):
        """Muestra las opciones disponibles para usuarios no autenticados."""
        print("\n" + "=" * 50)
        print("MENÚ PRINCIPAL")
        print("=" * 50)
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Listar usuarios registrados")
        print("4. Verificar certificado de usuario")
        print("0. Salir")
        print("=" * 50)

    def show_user_menu(self):
        """
        Muestra el menú  para el usuario autenticado.
        Las opciones disponibles cambian dinámicamente según el estado del usuario
        (si tiene claves generadas o certificado emitido).
        """
        print("\n" + "=" * 50)
        print(f"SESIÓN ACTIVA: {self.current_user['username']}")
        print("=" * 50)
        print("1. Ver mi información")

        # Lógica para mostrar opciones progresivas
        has_keys = self.current_user.get('has_keypair', False)
        has_cert = self.current_user.get('certificate_issued', False)

        if not has_keys:
            # Paso 1: Generación de claves obligatoria
            print("2. Generar mi par de claves (¡Primer paso requerido!)")
        elif not has_cert:
            # Paso 2: Solicitud de certificado obligatoria
            print("2. Solicitar certificado digital")
        else:
            # Paso 3: Operaciones completas habilitadas
            print("2. Subir, Firmar y Cifrar documento")
            print("3. Ver mi certificado digital")
            print("4. Verificar firma digital de un archivo") 

        print("0. Cerrar sesión")
        print("=" * 50)

    # -------------------------------------------------------------------------
    # Métodos de Lógica de Negocio (Controladores)
    # -------------------------------------------------------------------------

    def register_user(self):
        """
        Controlador para el registro de nuevos usuarios.
        Solicita datos, valida contraseñas y delega la creación al AuthManager.
        """
        print("\n" + "-" * 50)
        print("REGISTRO DE NUEVO USUARIO")
        print("-" * 50)
        try:
            username = input("Nombre de usuario: ").strip()
            email = input("Email: ").strip()
            print("\nRequisitos de seguridad: Mínimo 8 caracteres, mayúsculas, minúsculas y números.")
            
            # getpass evita que la contraseña se vea en la terminal
            password = getpass.getpass("Contraseña: ")
            password_confirm = getpass.getpass("Confirmar contraseña: ")

            if password != password_confirm:
                print("\n❌ Error: Las contraseñas no coinciden.")
                return

            user_info = self.auth_manager.register_user(username=username, password=password, email=email)
            print("\n✅ ¡Usuario registrado exitosamente!")
            self.logger.info(f"Registro completado para el usuario: {username}")
            
        except (UserAlreadyExistsError, ValueError) as e:
            print(f"\n❌ Error de registro: {e}")
        except Exception as e:
            print(f"\n❌ Error inesperado: {e}")
            self.logger.error(f"Excepción en registro: {e}", exc_info=True)

    def login_user(self):
        """
        Controlador para la autenticación de usuarios.
        Verifica credenciales y establece la sesión actual.
        """
        print("\n" + "-" * 50)
        print("INICIO DE SESIÓN")
        print("-" * 50)
        username = input("Usuario: ").strip()
        password = getpass.getpass("Contraseña: ")

        if self.auth_manager.authenticate_user(username, password):
            self.current_user = self.auth_manager.get_user_info(username)
            print(f"\n✅ Autenticación exitosa. Bienvenido, {username}.")
            self.logger.info(f"Sesión iniciada: {username}")
        else:
            print("\n❌ Credenciales inválidas.")
            self.logger.warning(f"Intento de acceso fallido: {username}")

    def list_users(self):
        """Muestra el directorio de usuarios y el estado de sus certificados."""
        users = self.auth_manager.list_users()
        print("\n" + "=" * 50)
        print(f"DIRECTORIO DE USUARIOS ({len(users)})")
        print("=" * 50)
        if not users:
            print("No hay usuarios registrados.")
        else:
            for user in users:
                cert_status = "✓" if user['certificate_issued'] else "✗"
                print(f"  [{cert_status}] {user['username']} ({user['email']})")
        print("\n  ✓ = Certificado Digital Emitido")
        print("  ✗ = Sin Certificado")
        print("=" * 50)

    def show_user_info(self):
        """Muestra los metadatos de la cuenta del usuario actual."""
        if not self.current_user: return
        
        # Refrescar datos desde la BD por si hubo cambios de estado
        self.current_user = self.auth_manager.get_user_info(self.current_user['username'])
        
        print("\n" + "=" * 50)
        print("PERFIL DE USUARIO")
        print("=" * 50)
        for key, value in self.current_user.items():
            print(f"  {key.replace('_', ' ').capitalize()}: {value}")
        print("=" * 50)

    def generate_user_keys(self):
        """
        Coordina la generación de claves RSA (Pública/Privada).
        La clave privada se cifra con la contraseña del usuario antes de guardarse.
        """
        username = self.current_user['username']
        print("\n" + "-" * 50)
        print("GENERACIÓN DE CLAVES ASIMÉTRICAS (RSA)")
        print("-" * 50)
        print("Nota: Su clave privada será cifrada usando su contraseña de login.")

        # Re-autenticación para operaciones sensibles
        password = getpass.getpass("Confirme su contraseña para proceder: ")
        if not self.auth_manager.authenticate_user(username, password):
            print("\n❌ Contraseña incorrecta. Operación abortada.")
            return

        if self.key_manager.generate_and_save_key_pair(username, password):
            # Actualizar estado en la base de datos de usuarios
            self.auth_manager.update_user_keypair_status(username, True)
            self.current_user['has_keypair'] = True
            print("\n✅ Claves generadas y almacenadas de forma segura.")
            print("\n📋 Siguiente paso: Solicite su certificado digital.")
        else:
            print("\n❌ Error: No se pudieron generar las claves (¿ya existen?).")

    def request_certificate(self):
        """
        Gestiona la solicitud de firma de certificado (CSR) a la CA Subordinada.
        Vincula la identidad del usuario con su clave pública.
        """
        username = self.current_user['username']
        email = self.current_user['email']

        print("\n" + "-" * 50)
        print("EMISIÓN DE CERTIFICADO DIGITAL")
        print("-" * 50)

        # Validaciones previas
        if not self.current_user.get('has_keypair', False):
            print("❌ Error: Debe generar sus claves antes de solicitar un certificado.")
            return

        if self.current_user.get('certificate_issued', False):
            print("⚠️  Aviso: Ya posee un certificado válido.")
            return

        print(f"Se emitirá un certificado X.509 para:")
        print(f"  Usuario: {username}")
        print(f"  Email:   {email}")

        confirm = input("\n¿Proceder con la emisión? (s/n): ").strip().lower()
        if confirm != 's':
            print("Operación cancelada.")
            return

        # Carga de la clave pública para incluirla en el certificado
        public_key = self.key_manager.load_public_key(username)
        if not public_key:
            print("❌ Error: No se encontró la clave pública.")
            return

        # Contraseña de la AC Subordinada
        SUB_CA_PASSWORD = "SubCa"

        # Emitir el certificado pasando la contraseña
        if self.pki_manager.issue_user_certificate(
                username,
                email,
                public_key,
                sub_ca_password=SUB_CA_PASSWORD
        ):

            self.auth_manager.update_user_certificate_status(username, True)
            self.current_user['certificate_issued'] = True
            print("\n✅ Certificado emitido y firmado por la AC Subordinada.")
            print(f"   Ubicación: {USER_CERTS_DIR / f'{username}.crt'}")
        else:
            print("\n❌ Fallo en la emisión del certificado.")

    def view_user_certificate(self):
        """
        Visualiza los detalles del certificado X.509 del usuario actual
        y valida su cadena de confianza contra la PKI.
        """
        username = self.current_user['username']

        print("\n" + "-" * 50)
        print("DETALLES DEL CERTIFICADO DIGITAL")
        print("-" * 50)

        cert = self.pki_manager.get_user_certificate(username)
        if not cert:
            print("❌ No se encontró ningún certificado asociado.")
            return

        # Mostrar campos relevantes del estándar X.509
        print(f"✓ Propietario (Subject): {cert.subject.rfc4514_string()}")
        print(f"  Emisor (Issuer):       {cert.issuer.rfc4514_string()}")
        print(f"  Válido desde:          {cert.not_valid_before}")
        print(f"  Válido hasta:          {cert.not_valid_after}")
        print(f"  Serial Number:         {cert.serial_number}")

        # Validación criptográfica de la cadena de confianza
        cert_path = USER_CERTS_DIR / f"{username}.crt"
        is_valid, message = self.pki_manager.verify_certificate_chain(cert_path)

        if is_valid:
            print(f"\n✅ Estado: CONFIABLE (Cadena de confianza verificada)")
        else:
            print(f"\n❌ Estado: NO CONFIABLE")
        print(f"   Detalle: {message}")

    def verify_any_certificate(self):
        """
        Permite validar el certificado de cualquier usuario del sistema.
        Útil para comprobar identidades de terceros.
        """
        print("\n" + "-" * 50)
        print("VERIFICACIÓN PÚBLICA DE CERTIFICADO")
        print("-" * 50)

        username = input("Ingrese el nombre de usuario a auditar: ").strip()

        cert_path = USER_CERTS_DIR / f"{username}.crt"
        if not cert_path.exists():
            print(f"❌ Certificado no encontrado para '{username}'.")
            return

        cert = self.pki_manager.get_user_certificate(username)
        print(f"\n✓ Certificado cargado para: {username}")
        print(f"  Subject: {cert.subject.rfc4514_string()}")
        print(f"  Vigencia: {cert.not_valid_before} - {cert.not_valid_after}")

        # Verificación de la firma de la CA en el certificado
        is_valid, message = self.pki_manager.verify_certificate_chain(cert_path)

        print("\n" + "=" * 50)
        if is_valid:
            print("✅ CERTIFICADO VÁLIDO")
            print("   La firma digital de la Autoridad de Certificación es correcta.")
        else:
            print("❌ CERTIFICADO INVÁLIDO O COMPROMETIDO")
        print(f"   Resultado: {message}")
        print("=" * 50)

    def verify_document_signature(self):
        """
        Verifica la integridad y autenticidad de un documento mediante su firma digital.
        Requiere el archivo original y el archivo .sig.
        """
        print("\n" + "-" * 50)
        print("VERIFICACIÓN DE FIRMA DIGITAL")
        print("-" * 50)
        
        file_path_str = input("Ruta del fichero original (sin cifrar): ").strip()
        sig_path_str = input("Ruta del fichero de firma (.sig): ").strip()
        signer_user = input("Nombre de usuario del supuesto firmante: ").strip()
        
        file_path = Path(file_path_str)
        sig_path = Path(sig_path_str)
        
        if not file_path.exists() or not sig_path.exists():
            print("❌ Error: No se encuentran los archivos especificados.")
            return
            
        original_data = file_path.read_bytes()
        signature_data = sig_path.read_bytes()
        
        print(f"\nVerificando firma criptográfica de '{signer_user}'...")
        is_valid = self.signature_manager.verify_signature(original_data, signature_data, signer_user)
        
        if is_valid:
            print("\n✅ FIRMA VÁLIDA: El documento es auténtico y no ha sido modificado.")
        else:
            print("\n❌ FIRMA INVÁLIDA: El documento ha sido alterado o la firma no corresponde al usuario.")

    def upload_document(self):
        """
        Proceso completo de aseguramiento de documentos.
        Realiza: Firma Digital (No Repudio) -> Cifrado Simétrico -> Cifrado Asimétrico de Claves.
        """
        username = self.current_user['username']
        print("\n" + "-" * 50)
        print("SUBIDA SEGURA DE DOCUMENTOS")
        print("-" * 50)

        # Prerrequisito: Tener certificado válido
        if not self.current_user.get('certificate_issued', False):
            print("❌ Requisito: Necesita un certificado digital activo.")
            return

        file_path_str = input("Ruta del archivo a procesar: ").strip()
        file_path = Path(file_path_str)

        if not file_path.exists() or not file_path.is_file():
            print(f"❌ Error: El archivo no existe o no es accesible.")
            return

        original_data = file_path.read_bytes()
        
        # --- FASE 1: FIRMA DIGITAL (Garantía de No Repudio) ---
        print("\n🔐 Fase 1: Firma Digital")
        print("Para garantizar el NO REPUDIO, se requiere autenticación para firmar.")
        
        # Solicitar contraseña específicamente para la operación de firma
        sign_password = getpass.getpass(f"Contraseña de firma para {username}: ")
        
        print("Generando firma RSA-PSS...")
        signature = self.signature_manager.sign_document(original_data, username, sign_password)
        
        if not signature:
            print("\n❌ Error: Fallo en la firma (posible contraseña incorrecta).")
            return
        print("✅ Documento firmado digitalmente.")

        # --- FASE 2: CIFRADO HÍBRIDO ---
        print("\n🔒 Fase 2: Cifrado y Encapsulamiento")

        # 1. Generación de clave simétrica efímera (AES-256)
        sym_key = self.sym_encryptor.generate_key()

        # 2. Cifrado del contenido (AES-GCM)
        encrypted_document = self.sym_encryptor.encrypt(original_data, sym_key)

        # 3. Carga de clave pública para proteger la clave simétrica
        public_key = self.key_manager.load_public_key(username)
        if not public_key:
            print("❌ Error crítico: Clave pública no disponible.")
            return

        # 4. Cifrado de la clave simétrica con RSA (KEM - Key Encapsulation Mechanism)
        encrypted_sym_key = self.asym_encryptor.encrypt(sym_key, public_key)

        # 5. Generación y protección de clave HMAC (Integridad del criptograma)
        hmac_key = self.hmac_manager.generate_key()
        hmac_tag = self.hmac_manager.generate_hmac(encrypted_document, hmac_key)
        encrypted_hmac_key = self.asym_encryptor.encrypt(hmac_key, public_key)

        # --- FASE 3: PERSISTENCIA ---
        user_docs_dir = DOCUMENTS_DIR / username
        user_docs_dir.mkdir(exist_ok=True)

        # Guardar payload cifrado
        encrypted_file_path = user_docs_dir / f"{file_path.name}.enc"
        encrypted_file_path.write_bytes(encrypted_document)

        # Guardar firma digital (detached signature)
        signature_path = user_docs_dir / f"{file_path.name}.sig"
        signature_path.write_bytes(signature)

        # Guardar metadatos necesarios para el descifrado
        metadata = {
            'encrypted_sym_key_hex': encrypted_sym_key.hex(),
            'encrypted_hmac_key_hex': encrypted_hmac_key.hex(),
            'hmac_tag': hmac_tag,
            'signature_file': signature_path.name
        }
        meta_file_path = user_docs_dir / f"{file_path.name}.meta"
        with open(meta_file_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        print("\n✅ PROCESO COMPLETADO EXITOSAMENTE")
        print(f"   [1] Cifrado: {encrypted_file_path.name}")
        print(f"   [2] Firma:   {signature_path.name}")
        print(f"   [3] Meta:    {meta_file_path.name}")
        self.logger.info(f"Documento asegurado y firmado: {file_path.name} por {username}.")

    # -------------------------------------------------------------------------
    # Bucles de Ejecución
    # -------------------------------------------------------------------------

    def user_session(self):
        """
        Bucle de sesión para usuarios autenticados.
        Gestiona la navegación del menú de usuario.
        """
        while True:
            # Recargar información del usuario para reflejar cambios de estado
            self.current_user = self.auth_manager.get_user_info(self.current_user['username'])
            self.show_user_menu()
            choice = input("\nSeleccione una opción: ").strip()

            if choice == "1":
                self.show_user_info()
            
            elif choice == "2":
                # Lógica condicional del paso 2
                if not self.current_user.get('has_keypair'):
                    self.generate_user_keys()
                elif not self.current_user.get('certificate_issued'):
                    self.request_certificate()
                else:
                    self.upload_document()
            
            elif choice == "3":
                # Ver certificado (Solo si existe)
                if self.current_user.get('certificate_issued'):
                    self.view_user_certificate()
                else:
                    print("\n⚠️  Opción no disponible en este estado.")
            
            elif choice == "4":
                # Verificar firma (Solo si existe certificado, implicando entorno listo)
                if self.current_user.get('certificate_issued'):
                   self.verify_document_signature()
                else:
                   print("\n⚠️  Debe configurar su entorno (claves/certificado) primero.")
            
            elif choice == "0":
                print(f"\n👋 Cerrando sesión...")
                self.logger.info(f"Cierre de sesión: {self.current_user['username']}")
                self.current_user = None
                break
            else:
                print("\n❌ Opción no reconocida.")
            
            input("\nPresione Enter para continuar...")

    def run(self):
        """
        Punto de entrada de la aplicación.
        Gestiona el bucle principal (Login/Registro/Salida).
        """
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
                elif choice == "4":
                    self.verify_any_certificate()
                elif choice == "0":
                    print("\n👋 Finalizando aplicación. Hasta pronto.")
                    self.logger.info("Aplicación finalizada por el usuario.")
                    break
                else:
                    print("\n❌ Opción no reconocida.")
                
                if not self.current_user:
                    input("\nPresione Enter para continuar...")


def main():
    """Función de arranque y manejo de excepciones globales."""
    try:
        setup_logging()
        app = SecureSendApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupción detectada. Saliendo...")
        logging.info("Salida forzada por teclado (Ctrl+C).")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error Crítico: {e}")
        logging.critical(f"Excepción no controlada: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()