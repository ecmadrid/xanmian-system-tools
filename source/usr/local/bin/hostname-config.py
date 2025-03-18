#!/usr/bin/env python3

import sys
import socket
import subprocess
import os
import shutil
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QHBoxLayout)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt

# Colores y estilo para Cinnamon en Linux Mint
CINNAMON_BG = "#2E2E2E"
CINNAMON_FG = "#FFFFFF"
CINNAMON_ACCENT = "#5294E2"
CINNAMON_HOVER = "#6AA8F7"  # Color más claro para el hover

def get_hostname_info():
    """Obtiene el hostname y dominio actuales."""
    hostname = socket.gethostname()
    try:
        result = subprocess.run(['hostnamectl', '--static'], capture_output=True, text=True)
        static_hostname = result.stdout.strip()
        domain = socket.getfqdn().replace(static_hostname + ".", "") if "." in socket.getfqdn() else ""
        return static_hostname, domain
    except Exception as e:
        return hostname, f"Error: {e}"

def set_hostname(new_hostname, new_domain=""):
    """Cambia el hostname y dominio usando pkexec."""
    try:
        full_hostname = new_hostname if not new_domain else f"{new_hostname}.{new_domain}"
        cmd = ['pkexec', 'hostnamectl', 'set-hostname', full_hostname]
        process = subprocess.run(cmd, capture_output=True, text=True)
        if process.returncode == 0:
            QMessageBox.information(None, "Éxito", "Hostname actualizado correctamente.")
            update_info()
        elif process.returncode in (126, 127):
            QMessageBox.critical(None, "Error", "Autenticación cancelada o pkexec no disponible.")
        else:
            QMessageBox.critical(None, "Error", f"No se pudo cambiar el hostname: {process.stderr}")
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Excepción al cambiar hostname: {e}")

class HostnameConfigApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Configuración de Hostname - Linux Mint")
        self.setGeometry(100, 100, 400, 300)
        self.setStyleSheet(f"background-color: {CINNAMON_BG}; color: {CINNAMON_FG};")

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout principal
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Etiquetas de información actual
        self.hostname_label = QLabel("Cargando hostname...", self)
        self.hostname_label.setStyleSheet(f"font-size: 14px; color: {CINNAMON_FG};")
        layout.addWidget(self.hostname_label)

        self.domain_label = QLabel("Cargando dominio...", self)
        self.domain_label.setStyleSheet(f"font-size: 14px; color: {CINNAMON_FG};")
        layout.addWidget(self.domain_label)

        # Campos de entrada
        layout.addWidget(QLabel("Nuevo Hostname:"))
        self.hostname_entry = QLineEdit(self)
        self.hostname_entry.setStyleSheet(f"background-color: #444; color: {CINNAMON_FG};")
        layout.addWidget(self.hostname_entry)

        layout.addWidget(QLabel("Nuevo Dominio (opcional):"))
        self.domain_entry = QLineEdit(self)
        self.domain_entry.setStyleSheet(f"background-color: #444; color: {CINNAMON_FG};")
        layout.addWidget(self.domain_entry)

        # Botones
        self.apply_button = QPushButton("Aplicar Cambios", self)
        self.apply_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {CINNAMON_ACCENT};
                color: {CINNAMON_FG};
                padding: 8px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {CINNAMON_HOVER};
            }}
        """)
        self.apply_button.clicked.connect(self.apply_changes)
        layout.addWidget(self.apply_button)

        self.refresh_button = QPushButton("Actualizar", self)
        self.refresh_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {CINNAMON_ACCENT};
                color: {CINNAMON_FG};
                padding: 8px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {CINNAMON_HOVER};
            }}
        """)
        self.refresh_button.clicked.connect(self.update_info)
        layout.addWidget(self.refresh_button)

        # Actualizar información al iniciar
        self.update_info()

        # Verificar que hostnamectl esté disponible
        if not shutil.which("hostnamectl"):
            QMessageBox.critical(None, "Error", "El comando 'hostnamectl' no está disponible. Asegúrate de que systemd esté instalado.")
            self.close()

    def update_info(self):
        """Actualiza la información mostrada en la interfaz."""
        hostname, domain = get_hostname_info()
        self.hostname_label.setText(f"Hostname actual: {hostname}")
        self.domain_label.setText(f"Dominio actual: {domain if domain else 'No configurado'}")
        self.hostname_entry.setText(hostname)
        self.domain_entry.setText(domain)

    def apply_changes(self):
        """Aplica los cambios ingresados por el usuario."""
        new_hostname = self.hostname_entry.text().strip()
        new_domain = self.domain_entry.text().strip()
        if not new_hostname:
            QMessageBox.warning(self, "Advertencia", "El hostname no puede estar vacío.")
            return
        if QMessageBox.question(self, "Confirmar", "¿Seguro que quieres cambiar el hostname y dominio?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            set_hostname(new_hostname, new_domain)

def main():
    app = QApplication(sys.argv)
    window = HostnameConfigApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
