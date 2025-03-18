#!/usr/bin/env python3

import sys
import os
import subprocess
import configparser
import shutil
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QTextEdit, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QComboBox, QLabel, QProgressBar, QMenu, QMessageBox, QWidget
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

# Determinar el directorio home del usuario real
if 'SUDO_USER' in os.environ:
    USER_HOME = os.path.expanduser(f"~{os.environ['SUDO_USER']}")
else:
    USER_HOME = os.path.expanduser("~")

class SystemdGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gestor de Servicios Systemd (Linux Mint)")
        self.setGeometry(100, 100, 900, 600)

        self.config_file = os.path.expanduser("~/.systemd_gui_config")
        self.config = configparser.ConfigParser()
        self.load_config()

        # Variables de estado
        self.all_services = []
        self.selected_service = None

        # Crear la interfaz
        self.initUI()

    def initUI(self):
        # Frame principal
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Barra superior
        top_layout = QHBoxLayout()
        main_layout.addLayout(top_layout)

        self.refresh_button = QPushButton("Refrescar")
        self.refresh_button.clicked.connect(self.refresh_services)
        top_layout.addWidget(self.refresh_button)

        self.exit_button = QPushButton("Salir")
        self.exit_button.clicked.connect(self.quit)
        top_layout.addWidget(self.exit_button)

        self.search_label = QLabel("Buscar:")
        top_layout.addWidget(self.search_label)

        self.search_entry = QLineEdit()
        self.search_entry.returnPressed.connect(self.refresh_services)
        top_layout.addWidget(self.search_entry)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Todos", "Activos", "Habilitados", "Servicios Web"])
        self.filter_combo.currentIndexChanged.connect(self.refresh_services)  # Refrescar al cambiar
        top_layout.addWidget(self.filter_combo)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Claro", "Oscuro"])
        self.theme_combo.currentIndexChanged.connect(self.change_theme)
        top_layout.addWidget(self.theme_combo)

        # Barra de progreso
        self.progress = QProgressBar()
        self.progress.setMaximum(100)
        self.progress.setVisible(False)
        main_layout.addWidget(self.progress)

        # Panel principal
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Servicio", "Activo", "Habilitado"])
        self.tree.setColumnWidth(0, 250)
        self.tree.setColumnWidth(1, 50)
        self.tree.setColumnWidth(2, 50)
        self.tree.itemSelectionChanged.connect(self.show_service_details)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        main_layout.addWidget(self.tree)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        main_layout.addWidget(self.details_text)

        # Menú contextual
        self.context_menu = QMenu(self)
        self.context_menu.addAction("Iniciar", self.start_service)
        self.context_menu.addAction("Parar", self.stop_service)
        self.context_menu.addAction("Reiniciar", self.restart_service)
        self.context_menu.addAction("Habilitar", self.enable_service)
        self.context_menu.addAction("Deshabilitar", self.disable_service)
        self.context_menu.addAction("Ver logs", self.view_logs)

        # Cargar servicios
        self.refresh_services()

    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.config["Settings"] = {}

    def save_config(self):
        self.config["Settings"]["last_search"] = self.search_entry.text()
        self.config["Settings"]["theme"] = self.theme_combo.currentText()
        with open(self.config_file, "w") as f:
            self.config.write(f)

    def change_theme(self):
        theme = self.theme_combo.currentText()
        if theme == "Oscuro":
            self.setStyleSheet("""
                QWidget { background-color: #2E2E2E; color: #FFFFFF; }
                QTextEdit { background-color: #2E2E2E; color: #FFFFFF; }
                QTreeWidget { background-color: #2E2E2E; color: #FFFFFF; }
            """)
        else:
            self.setStyleSheet("""
                QWidget { background-color: #D9D9D9; color: #000000; }
                QTextEdit { background-color: white; color: black; }
                QTreeWidget { background-color: white; color: black; }
            """)

    def get_services(self):
        try:
            result = subprocess.check_output(
                ["systemctl", "list-units", "--type=service", "--all"],
                text=True
            )
            services = []
            for line in result.splitlines():
                if ".service" in line and "loaded" in line:
                    parts = line.split()
                    service_name = parts[0]
                    active_state = parts[2] if len(parts) > 2 else "unknown"
                    try:
                        enabled_output = subprocess.check_output(
                            ["systemctl", "is-enabled", service_name],
                            text=True, stderr=subprocess.STDOUT
                        ).strip()
                        enabled = "enabled" in enabled_output
                    except subprocess.CalledProcessError:
                        enabled = False
                    services.append((service_name, active_state, enabled))
            return services
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"No se pudo listar servicios: {e}")
            return []

    def refresh_services(self):
        self.progress.setVisible(True)
        self.tree.clear()
        self.all_services = self.get_services()
        self.filter_services()
        self.progress.setVisible(False)

    def filter_services(self):
        search_term = self.search_entry.text().lower()
        filter_type = self.filter_combo.currentText()

        web_services = ["apache2", "nginx", "lighttpd"]  # Ajustado para Mint/Ubuntu
        for service, active, enabled in self.all_services:
            if search_term in service.lower():
                if filter_type == "Activos" and active != "active":
                    continue
                if filter_type == "Habilitados" and not enabled:
                    continue
                if filter_type == "Servicios Web" and not any(ws in service for ws in web_services):
                    continue
                item = QTreeWidgetItem(self.tree)
                item.setText(0, service)
                item.setText(1, "●" if active == "active" else "○")
                item.setText(2, "●" if enabled else "○")
                item.setForeground(1, QColor("green") if active == "active" else QColor("red"))
                item.setForeground(2, QColor("green") if enabled else QColor("red"))

    def show_context_menu(self, position):
        item = self.tree.itemAt(position)
        if item:
            self.selected_service = item.text(0)
            self.context_menu.exec_(self.tree.viewport().mapToGlobal(position))

    def show_service_details(self):
        selected_items = self.tree.selectedItems()
        if selected_items:
            service = selected_items[0].text(0)
            try:
                details = subprocess.check_output(
                    ["systemctl", "status", service], text=True
                )
                self.details_text.setPlainText(details)
            except subprocess.CalledProcessError as e:
                self.details_text.setPlainText(f"Error al obtener detalles: {e}")

    def run_systemctl(self, command, service):
        if QMessageBox.question(self, "Confirmar", f"¿Seguro que quieres {command} el servicio {service}?") == QMessageBox.Yes:
            try:
                cmd = ["pkexec", "systemctl", command, service]
                process = subprocess.run(cmd, check=True, text=True, capture_output=True)
                QMessageBox.information(self, "Éxito", f"Servicio {service} {command} correctamente.")
                self.refresh_services()
                self.show_service_details()
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Error", f"No se pudo {command} el servicio {service}: {e.output or e}")

    def start_service(self):
        if self.selected_service:
            self.run_systemctl("start", self.selected_service)

    def stop_service(self):
        if self.selected_service:
            self.run_systemctl("stop", self.selected_service)

    def restart_service(self):
        if self.selected_service:
            self.run_systemctl("restart", self.selected_service)

    def enable_service(self):
        if self.selected_service:
            self.run_systemctl("enable", self.selected_service)

    def disable_service(self):
        if self.selected_service:
            self.run_systemctl("disable", self.selected_service)

    def view_logs(self):
        if self.selected_service:
            try:
                logs = subprocess.check_output(
                    ["journalctl", "-u", self.selected_service, "-n", "50"], text=True
                )
                log_window = QTextEdit()
                log_window.setWindowTitle(f"Logs de {self.selected_service}")
                log_window.setPlainText(logs)
                log_window.setReadOnly(True)
                log_window.resize(600, 400)
                log_window.show()
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Error", f"No se pudieron obtener logs: {e}")

    def quit(self):
        self.save_config()
        QApplication.quit()

if __name__ == "__main__":
    # Verificar dependencias
    if not shutil.which("systemctl") or not shutil.which("pkexec"):
        print("Error: Se requiere 'systemctl' y 'pkexec'. Instálalos con 'sudo apt install systemd policykit-1'.")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = SystemdGUI()
    window.show()
    sys.exit(app.exec_())
