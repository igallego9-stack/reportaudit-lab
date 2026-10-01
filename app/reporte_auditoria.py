"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente. En producción desde hace 18 meses; nadie lo ha
revisado desde entonces.

Punto de partida del Laboratorio 1 de Calidad de Software: este módulo
contiene problemas reales de seguridad, sembrados a propósito, que el
estudiante debe encontrar (primero a mano y luego con herramientas) y
corregir. No uses este código como ejemplo de cómo hacer las cosas.
"""

import hashlib
import os
import sqlite3
import subprocess

import yaml

# --- Configuración cargada de forma segura desde variables de entorno ---
NOTIFICATION_API_KEY = os.environ.get("NOTIFICATION_API_KEY")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML de forma segura."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # Uso de safe_load para evitar deserialización insegura de objetos (CWE-502)
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente utilizando consultas parametrizadas."""
    conexion = sqlite3.connect(ruta_db)
    cursor = conexion.cursor()
    # Consulta parametrizada para prevenir inyección SQL (SQLi / CWE-89)
    query = "SELECT * FROM reportes WHERE cliente = ?"
    cursor.execute(query, (nombre_cliente,))
    resultados = cursor.fetchall()
    conexion.close()
    return resultados


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF validando el nombre del archivo para prevenir inyección."""
    # Validación estricta de nombre y extensión para prevenir Command Injection (CWE-78)
    nombre_limpio = os.path.basename(nombre_archivo)
    if not nombre_limpio.endswith(".html"):
        raise ValueError("Formato de archivo invalido. Solo se admiten archivos .html")

    salida_pdf = f"{nombre_limpio}.pdf"
    subprocess.run(["wkhtmltopdf", nombre_limpio, salida_pdf], check=True, shell=False)
    return salida_pdf


def hash_password_legacy(password):
    """Genera el hash de una contraseña usando PBKDF2 HMAC SHA-256 (CWE-916)."""
    # Se utiliza PBKDF2 con sal e iteraciones para cumplir las normas de hashing seguro
    salt = b"reporte_auditoria_salt_seguro"
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    print(f"[NotifyAPI] -> {email}: {mensaje}")
    return True