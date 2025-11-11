# -*- coding: utf-8 -*-

"""
Módulo de gestión de PKI (Public Key Infrastructure) para la práctica de
Criptografía y Seguridad Informática.

Este módulo implementa la jerarquía de Autoridades de Certificación (CAs)
descrita en el enunciado de la práctica. Concretamente, establece una
infraestructura de clave pública de dos niveles:

1.  **Autoridad de Certificación Raíz (AC1):** Es la máxima entidad de confianza.
    Se crea con un certificado autofirmado, lo que significa que ella misma
    garantiza la validez de su propia clave pública. Es el "ancla de confianza"
    (trust anchor) de toda la PKI. Su principal y única función es firmar los
    certificados de las autoridades subordinadas.

2.  **Autoridad de Certificación Subordinada (AC2):** Es una entidad de confianza
    intermedia. Su certificado está firmado por la AC Raíz (AC1). Su propósito
    es emitir, firmar y gestionar los certificados de los usuarios finales
    (end-entities), como se pide en la práctica. Esta separación de roles
    (Raíz para firmar CAs, Subordinada para firmar usuarios) es una buena
    práctica de seguridad. Permite mantener la clave de la AC Raíz offline
    y segura, usando solo la clave de la AC Subordinada para operaciones
    más frecuentes.

El módulo utiliza la librería `cryptography` de Python para manejar todas las
operaciones criptográficas necesarias: generación de claves, creación de
certificados X.509 y validación de la cadena de confianza.
"""

# Se importa el módulo logging para registrar información, advertencias y errores
# durante la ejecución, lo cual es fundamental para la depuración y auditoría.
import logging
# Path de pathlib permite manejar rutas de sistema de archivos de forma
# compatible con distintos sistemas operativos.
from pathlib import Path
# datetime y timedelta se usan para establecer los periodos de validez de los
# certificados (fechas "not valid before" y "not valid after").
from datetime import datetime, timedelta
# Tipos opcionales y tuplas para el chequeo de tipos estáticos, mejorando la
# claridad y robustez del código.
from typing import Optional, Tuple

# Componentes específicos de la librería `cryptography`.
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Importación de la configuración centralizada del proyecto. Esto permite
# modificar parámetros como el tamaño de las claves o los nombres de la
# organización sin tener que cambiar el código fuente.
from config import (
    CA_ROOT_DIR,
    CA_SUB_DIR,
    USER_CERTS_DIR,
    PKI_CONFIG,
    ORG_INFO
)

# Se obtiene una instancia del logger para este módulo. Esto permite configurar
# el nivel de detalle de los mensajes de log de forma centralizada.
logger = logging.getLogger(__name__)


class PKIManager:
    """
    Gestor de la Infraestructura de Clave Pública (PKI).

    Esta clase encapsula toda la lógica para crear y administrar la jerarquía de
    certificados digitales. Proporciona métodos para:
    - Crear la Autoridad de Certificación Raíz (AC1).
    - Crear una Autoridad de Certificación Subordinada (AC2) firmada por la AC1.
    - Emitir certificados para usuarios finales firmados por la AC2.
    - Verificar la cadena de confianza completa de un certificado de usuario.
    """

    def __init__(self):
        """
        Inicializa el gestor de PKI.

        Define las rutas a los archivos clave de la infraestructura (claves
        privadas y certificados de las CAs) basándose en la configuración importada.
        """
        # Ruta al certificado de la Autoridad Raíz (AC1)
        self.root_ca_cert_path = CA_ROOT_DIR / "root_ca.crt"
        # Ruta a la clave privada de la Autoridad Raíz (AC1)
        self.root_ca_key_path = CA_ROOT_DIR / "root_ca.key"
        # Ruta al certificado de la Autoridad Subordinada (AC2)
        self.sub_ca_cert_path = CA_SUB_DIR / "sub_ca.crt"
        # Ruta a la clave privada de la Autoridad Subordinada (AC2)
        self.sub_ca_key_path = CA_SUB_DIR / "sub_ca.key"

        logger.info("PKIManager inicializado")

    def _generate_private_key(self) -> rsa.RSAPrivateKey:
        """
        Genera una nueva clave privada RSA.

        Esta es una función auxiliar interna utilizada para crear las claves
        de las CAs y de los usuarios.

        Returns:
            rsa.RSAPrivateKey: Un objeto de clave privada RSA.
        """
        private_key = rsa.generate_private_key(
            # El exponente público es un número fijo. 65537 es un valor estándar
            # y eficiente que equilibra seguridad y rendimiento.
            public_exponent=65537,
            # El tamaño de la clave (en bits) se toma de la configuración.
            # Un tamaño mayor (ej. 2048, 4096) ofrece más seguridad.
            key_size=PKI_CONFIG['KEY_SIZE'],
            # Se especifica el backend criptográfico a usar. default_backend()
            # selecciona la mejor implementación disponible (normalmente OpenSSL).
            backend=default_backend()
        )
        logger.debug(f"Clave privada RSA de {PKI_CONFIG['KEY_SIZE']} bits generada")
        return private_key

    def _save_private_key(self, private_key: rsa.RSAPrivateKey,
                          path: Path, password: Optional[str] = None):
        """
        Guarda una clave privada en un archivo en formato PEM.

        El formato PEM (Privacy-Enhanced Mail) es un estándar para almacenar
        datos criptográficos en formato de texto (Base64).

        Args:
            private_key (rsa.RSAPrivateKey): La clave privada a guardar.
            path (Path): La ruta del archivo donde se guardará la clave.
            password (Optional[str]): Contraseña opcional para cifrar la clave
                                      privada. Es una práctica de seguridad
                                      altamente recomendada.
        """
        # Si se proporciona una contraseña, se utiliza el mejor algoritmo de
        # cifrado disponible para proteger el archivo de la clave.
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            # Si no hay contraseña, la clave se guarda sin cifrar.
            encryption = serialization.NoEncryption()

        # Se abre el archivo en modo de escritura binaria ('wb').
        with open(path, 'wb') as f:
            # Se serializa el objeto de clave privada a formato PEM.
            # PKCS#8 es un formato estándar para almacenar claves privadas.
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption
            ))
        logger.info(f"Clave privada guardada en: {path}")

    def _save_certificate(self, cert: x509.Certificate, path: Path):
        """
        Guarda un certificado X.509 en un archivo en formato PEM.

        Args:
            cert (x509.Certificate): El certificado a guardar.
            path (Path): La ruta del archivo donde se guardará el certificado.
        """
        # Los certificados, al ser información pública, no se cifran.
        with open(path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info(f"Certificado guardado en: {path}")

    def _load_private_key(self, path: Path,
                          password: Optional[str] = None) -> rsa.RSAPrivateKey:
        """
        Carga una clave privada desde un archivo en formato PEM.

        Args:
            path (Path): La ruta del archivo de la clave privada.
            password (Optional[str]): La contraseña si la clave está cifrada.

        Returns:
            rsa.RSAPrivateKey: El objeto de clave privada cargado.
        """
        with open(path, 'rb') as f:
            # Si se proporciona contraseña, se convierte a bytes.
            pwd = password.encode('utf-8') if password else None
            # Se deserializa el archivo PEM a un objeto de clave privada.
            return serialization.load_pem_private_key(
                f.read(),
                password=pwd,
                backend=default_backend()
            )

    def _load_certificate(self, path: Path) -> x509.Certificate:
        """
        Carga un certificado X.509 desde un archivo en formato PEM.

        Args:
            path (Path): La ruta del archivo del certificado.

        Returns:
            x509.Certificate: El objeto de certificado cargado.
        """
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def create_root_ca(self, password: Optional[str] = None) -> bool:
        """
        Crea la Autoridad de Certificación Raíz (AC1) con un certificado autofirmado.

        Este método realiza todos los pasos para establecer el ancla de confianza de la PKI:
        1. Genera un par de claves (pública/privada) para la AC Raíz.
        2. Construye un certificado X.509 con la información de la AC Raíz.
        3. El emisor (issuer) y el sujeto (subject) del certificado son la misma AC Raíz.
        4. Se añaden extensiones críticas que la identifican como una CA.
        5. El certificado se firma usando su propia clave privada (autofirmado).
        6. Guarda la clave privada (idealmente cifrada) y el certificado público.

        Args:
            password (Optional[str]): Contraseña opcional para proteger la clave privada de la AC Raíz.

        Returns:
            bool: True si se creó correctamente, False si ya existía.
        """
        if self.root_ca_cert_path.exists():
            logger.warning("La AC Raíz ya existe. No se tomarán acciones.")
            return False

        logger.info("=" * 60)
        logger.info("CREANDO AUTORIDAD DE CERTIFICACIÓN RAÍZ (AC1)")
        logger.info("=" * 60)

        # 1. Generar par de claves para la AC Raíz
        private_key = self._generate_private_key()
        public_key = private_key.public_key()

        # 2. Crear el "Subject" y el "Issuer". En un certificado autofirmado, son idénticos.
        # El Subject contiene los datos de identidad del propietario del certificado.
        # El Issuer contiene los datos de la entidad que emitió y firmó el certificado.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ORG_INFO['COUNTRY']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ORG_INFO['STATE']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ORG_INFO['LOCALITY']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_INFO['ORGANIZATION']),
            # El Common Name (CN) es el identificador principal.
            x509.NameAttribute(NameOID.COMMON_NAME, ORG_INFO['ROOT_CN']),
        ])

        # 3. Construir el esqueleto del certificado
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.utcnow() + timedelta(days=PKI_CONFIG['ROOT_CA_VALIDITY_DAYS'])
        )

        # 4. Añadir extensiones X.509. Estas definen las propiedades y restricciones del certificado.
        # La extensión BasicConstraints indica si el certificado pertenece a una CA.
        cert_builder = cert_builder.add_extension(
            # ca=True: Es una CA. critical=True: Un sistema que no entienda esta extensión debe rechazar el certificado.
            # path_length=1: Esta CA puede crear una cadena de CAs de 1 nivel por debajo. Perfecto para nuestra AC2.
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )

        # La extensión KeyUsage define los propósitos para los que se puede usar la clave pública.
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,  # ¡CRÍTICO! Permite a esta clave firmar otros certificados.
                crl_sign=True,  # Permite firmar Listas de Revocación de Certificados.
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # SubjectKeyIdentifier proporciona un identificador único para la clave pública del certificado.
        # Ayuda a distinguirla de otras claves, especialmente si una entidad renueva su certificado.
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )

        # 5. Firmar el certificado con su propia clave privada.
        cert = cert_builder.sign(
            private_key,
            hashes.SHA256(),  # Se usa SHA-256 como algoritmo de hash para la firma.
            default_backend()
        )

        # 6. Guardar la clave privada y el certificado.
        self._save_private_key(private_key, self.root_ca_key_path, password)
        self._save_certificate(cert, self.root_ca_cert_path)

        logger.info("✅ Autoridad de Certificación Raíz (AC1) creada exitosamente")
        logger.info(f"  - Common Name: {ORG_INFO['ROOT_CN']}")
        logger.info(f"  - Validez: {PKI_CONFIG['ROOT_CA_VALIDITY_DAYS']} días")
        logger.info(f"  - Tamaño de clave: {PKI_CONFIG['KEY_SIZE']} bits")
        logger.info(f"  - Algoritmo de firma: RSA con SHA-256")
        logger.info("=" * 60)

        return True

    def create_subordinate_ca(self, root_ca_password: Optional[str] = None,
                              sub_ca_password: Optional[str] = None) -> bool:
        """
        Crea la Autoridad de Certificación Subordinada (AC2) firmada por la AC Raíz.

        Este método establece el segundo nivel de la jerarquía de confianza.
        1. Carga la clave privada y el certificado de la AC Raíz.
        2. Genera un nuevo par de claves para la AC Subordinada.
        3. Construye un certificado donde el 'subject' es la AC Subordinada y el 'issuer' es la AC Raíz.
        4. Añade extensiones que la identifican como una CA, pero sin capacidad de crear más CAs.
        5. Firma el nuevo certificado con la clave privada de la AC Raíz.

        Args:
            root_ca_password (Optional[str]): Contraseña de la clave privada de la AC Raíz.
            sub_ca_password (Optional[str]): Contraseña opcional para proteger la clave de la AC Subordinada.

        Returns:
            bool: True si se creó correctamente, False si ya existe o si falta la AC Raíz.
        """
        if self.sub_ca_cert_path.exists():
            logger.warning("La AC Subordinada ya existe. No se tomarán acciones.")
            return False

        if not self.root_ca_cert_path.exists():
            logger.error("No se puede crear la AC Subordinada porque la AC Raíz no existe.")
            return False

        logger.info("=" * 60)
        logger.info("CREANDO AUTORIDAD DE CERTIFICACIÓN SUBORDINADA (AC2)")
        logger.info("=" * 60)

        # 1. Cargar la AC Raíz, que actuará como firmante.
        root_ca_key = self._load_private_key(self.root_ca_key_path, root_ca_password)
        root_ca_cert = self._load_certificate(self.root_ca_cert_path)

        # 2. Generar par de claves para la AC Subordinada
        sub_private_key = self._generate_private_key()
        sub_public_key = sub_private_key.public_key()

        # 3. Crear el Subject de la AC Subordinada y el Issuer (la AC Raíz)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ORG_INFO['COUNTRY']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ORG_INFO['STATE']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ORG_INFO['LOCALITY']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_INFO['ORGANIZATION']),
            x509.NameAttribute(NameOID.COMMON_NAME, ORG_INFO['SUB_CN']),
        ])
        # El emisor (issuer) es la AC Raíz. Esto es lo que crea la cadena de confianza.
        issuer = root_ca_cert.subject

        # Construir el certificado
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(sub_public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.utcnow() + timedelta(days=PKI_CONFIG['SUB_CA_VALIDITY_DAYS'])
        )

        # 4. Añadir extensiones
        cert_builder = cert_builder.add_extension(
            # Es una CA (ca=True), pero path_length=0 le prohíbe crear más CAs por debajo de ella.
            # Esto limita la cadena a dos niveles (Raíz -> Subordinada), como pide la práctica.
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )

        cert_builder = cert_builder.add_extension(
            # El uso de clave es similar al de la raíz: puede firmar certificados y CRLs.
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )

        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(sub_public_key),
            critical=False,
        )

        # AuthorityKeyIdentifier: ¡Extensión CLAVE para la cadena!
        # Contiene el identificador (SubjectKeyIdentifier) del certificado de la CA que firmó este.
        # Así, un sistema puede encontrar fácilmente el certificado del emisor (la AC Raíz) para verificar la firma.
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_ca_key.public_key()),
            critical=False,
        )

        # 5. Firmar el certificado de la AC Subordinada con la clave privada de la AC Raíz
        cert = cert_builder.sign(
            root_ca_key,
            hashes.SHA256(),
            default_backend()
        )

        # Guardar la clave y el certificado de la AC Subordinada
        self._save_private_key(sub_private_key, self.sub_ca_key_path, sub_ca_password)
        self._save_certificate(cert, self.sub_ca_cert_path)

        logger.info("✅ Autoridad de Certificación Subordinada (AC2) creada exitosamente")
        logger.info(f"  - Common Name: {ORG_INFO['SUB_CN']}")
        logger.info(f"  - Validez: {PKI_CONFIG['SUB_CA_VALIDITY_DAYS']} días")
        logger.info(f"  - Firmada por: {ORG_INFO['ROOT_CN']}")
        logger.info(f"  - Tamaño de clave: {PKI_CONFIG['KEY_SIZE']} bits")
        logger.info("=" * 60)

        return True

    def issue_user_certificate(self, username: str, email: str,
                               public_key: rsa.RSAPublicKey,
                               sub_ca_password: Optional[str] = None) -> bool:
        """
        Emite un certificado digital para un usuario final (end-entity).

        Este certificado es el que usarán los usuarios en la aplicación. Vincula su
        identidad (nombre, email) con su clave pública. Está firmado por la AC Subordinada.

        Args:
            username (str): Nombre del usuario (será el Common Name del certificado).
            email (str): Email del usuario.
            public_key (rsa.RSAPublicKey): La clave pública del usuario para la cual se emite el certificado.
            sub_ca_password (Optional[str]): Contraseña de la clave privada de la AC Subordinada.

        Returns:
            bool: True si el certificado se emitió correctamente.
        """
        if not self.sub_ca_cert_path.exists():
            logger.error("No se puede emitir certificado de usuario porque la AC Subordinada no existe.")
            return False

        logger.info("=" * 60)
        logger.info(f"EMITIENDO CERTIFICADO PARA USUARIO: {username}")
        logger.info("=" * 60)

        # Cargar la AC Subordinada, que actuará como firmante.
        sub_ca_key = self._load_private_key(self.sub_ca_key_path, sub_ca_password)
        sub_ca_cert = self._load_certificate(self.sub_ca_cert_path)

        # Crear el Subject con los datos del usuario.
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, ORG_INFO['COUNTRY']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ORG_INFO['STATE']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ORG_INFO['LOCALITY']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_INFO['ORGANIZATION']),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])

        # El issuer es la AC Subordinada.
        issuer = sub_ca_cert.subject

        # Construir el certificado
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.utcnow() + timedelta(days=PKI_CONFIG['USER_CERT_VALIDITY_DAYS'])
        )

        # Extensiones para un certificado de usuario final.
        # BasicConstraints: ca=False es CRÍTICO. Indica que este certificado NO es de una CA
        # y no puede usarse para firmar otros certificados.
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        # KeyUsage: Define para qué puede usarse la clave. Por ejemplo, para firmas digitales
        # (`digital_signature`) o para cifrar otras claves (`key_encipherment`).
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False
            ),
            critical=True,
        )

        # ExtendedKeyUsage: Especifica usos más concretos. Muy común en TLS/SSL y S/MIME.
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,  # Autenticación de cliente (ej. en una conexión web)
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,  # Para firmar/cifrar correos
            ]),
            critical=False,
        )

        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )

        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(sub_ca_key.public_key()),
            critical=False,
        )

        # SubjectAlternativeName: Permite asociar otras identidades al certificado,
        # como un email o un nombre de dominio. Es una práctica estándar hoy en día.
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )

        # Firmar el certificado del usuario con la clave privada de la AC Subordinada
        cert = cert_builder.sign(
            sub_ca_key,
            hashes.SHA256(),
            default_backend()
        )

        # Guardar el certificado del usuario en su directorio correspondiente.
        user_cert_path = USER_CERTS_DIR / f"{username}.crt"
        self._save_certificate(cert, user_cert_path)

        logger.info("✅ Certificado de usuario emitido exitosamente")
        logger.info(f"  - Usuario: {username}")
        logger.info(f"  - Email: {email}")
        logger.info(f"  - Validez: {PKI_CONFIG['USER_CERT_VALIDITY_DAYS']} días")
        logger.info(f"  - Firmado por: {ORG_INFO['SUB_CN']}")
        logger.info(f"  - Guardado en: {user_cert_path}")
        logger.info("=" * 60)

        return True

    def verify_certificate_chain(self, user_cert_path: Path) -> Tuple[bool, str]:
        """
        Verifica la cadena completa de confianza de un certificado de usuario.

        Este es el proceso de validación de la PKI. Comprueba secuencialmente:
        1. La firma del certificado del usuario con la clave pública de la AC Subordinada.
        2. La firma del certificado de la AC Subordinada con la clave pública de la AC Raíz.
        3. Que todos los certificados en la cadena (Usuario, AC Sub, AC Raíz) estén
           dentro de su período de validez.

        Args:
            user_cert_path (Path): La ruta al certificado del usuario que se quiere validar.

        Returns:
            Tuple[bool, str]: Una tupla con un booleano indicando si la cadena es válida
                              y un mensaje explicando el resultado.
        """
        try:
            # Cargar todos los certificados que forman la cadena de confianza.
            user_cert = self._load_certificate(user_cert_path)
            sub_ca_cert = self._load_certificate(self.sub_ca_cert_path)
            root_ca_cert = self._load_certificate(self.root_ca_cert_path)

            # --- VERIFICACIÓN DE FIRMAS ---
            # 1. Verificar que la clave pública de la AC Subordinada valida la firma del certificado del usuario.
            #    Esto prueba que la AC Subordinada realmente emitió este certificado.
            sub_ca_public_key = sub_ca_cert.public_key()
            try:
                sub_ca_public_key.verify(
                    user_cert.signature,
                    user_cert.tbs_certificate_bytes,  # tbs = To Be Signed (la parte del cert que se firma)
                    padding.PKCS1v15(),
                    user_cert.signature_hash_algorithm,
                )
                logger.info("Firma del certificado de usuario verificada por AC Subordinada [OK]")
            except Exception:
                msg = "¡FALLO! El certificado de usuario no está firmado correctamente por la AC Subordinada."
                logger.error(msg)
                return False, msg

            # 2. Verificar que la clave pública de la AC Raíz valida la firma del certificado de la AC Subordinada.
            #    Esto prueba que la AC Raíz confía en la AC Subordinada.
            root_ca_public_key = root_ca_cert.public_key()
            try:
                root_ca_public_key.verify(
                    sub_ca_cert.signature,
                    sub_ca_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sub_ca_cert.signature_hash_algorithm,
                )
                logger.info("Firma del certificado de AC Subordinada verificada por AC Raíz [OK]")
            except Exception:
                msg = "¡FALLO! El certificado de AC Subordinada no está firmado correctamente por la AC Raíz."
                logger.error(msg)
                return False, msg

            # --- VERIFICACIÓN DE VALIDEZ TEMPORAL ---
            now = datetime.utcnow()
            if user_cert.not_valid_before > now or user_cert.not_valid_after < now:
                msg = "¡FALLO! El certificado de usuario ha expirado o aún no es válido."
                logger.error(msg)
                return False, msg

            if sub_ca_cert.not_valid_before > now or sub_ca_cert.not_valid_after < now:
                msg = "¡FALLO! El certificado de la AC Subordinada ha expirado o aún no es válido."
                logger.error(msg)
                return False, msg

            if root_ca_cert.not_valid_before > now or root_ca_cert.not_valid_after < now:
                msg = "¡FALLO! El certificado de la AC Raíz ha expirado o aún no es válido."
                logger.error(msg)
                return False, msg

            logger.info("Períodos de validez de todos los certificados en la cadena [OK]")

            # Si todas las verificaciones pasan, la cadena es válida.
            msg = "✅ La cadena de certificados es válida."
            logger.info(msg)
            return True, msg

        except FileNotFoundError as e:
            logger.error(f"Error de archivo no encontrado al verificar la cadena: {e}")
            return False, f"Falta un archivo de certificado necesario para la verificación: {e.filename}"
        except Exception as e:
            logger.error(f"Error inesperado verificando la cadena de certificados: {e}")
            return False, f"Error durante la verificación: {str(e)}"

    def get_user_certificate(self, username: str) -> Optional[x509.Certificate]:
        """
        Obtiene el certificado de un usuario por su nombre.

        Args:
            username (str): El nombre de usuario.

        Returns:
            Optional[x509.Certificate]: El objeto del certificado si existe, sino None.
        """
        user_cert_path = USER_CERTS_DIR / f"{username}.crt"
        if not user_cert_path.exists():
            return None
        return self._load_certificate(user_cert_path)

    def pki_exists(self) -> bool:
        """
        Verifica si la infraestructura PKI (Raíz y Subordinada) ya ha sido creada.

        Returns:
            bool: True si los certificados de ambas CAs existen, False en caso contrario.
        """
        return (self.root_ca_cert_path.exists() and
                self.sub_ca_cert_path.exists())


# Este bloque se ejecuta solo si el script es llamado directamente desde la terminal.
# Es útil para realizar pruebas o una configuración inicial.
if __name__ == "__main__":
    # Configuración básica del logging para mostrar mensajes informativos en la consola.
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
