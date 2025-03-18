#!/usr/bin/env python3

import sys
import os
import subprocess
import configparser
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                             QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, 
                             QComboBox, QLabel, QTextEdit, QMessageBox, 
                             QTableWidget, QTableWidgetItem, QFormLayout, 
                             QDialog, QDialogButtonBox, QFileDialog, QCheckBox)
from PyQt5.QtCore import QCoreApplication

class ShareDialog(QDialog):
    def __init__(self, parent=None, share_name="", share_data=None, is_usershare=False):
        super().__init__(parent)
        self.setWindowTitle("Configurar Compartido" if not share_name else f"Editar {share_name}")
        self.share_name = share_name
        self.share_data = share_data if share_data else {}
        self.is_usershare = is_usershare
        self.initUI()

    def initUI(self):
        layout = QFormLayout()

        self.name_input = QLineEdit(self.share_name)
        self.name_input.setEnabled(not self.share_name)
        layout.addRow(QLabel("Nombre:"), self.name_input)

        self.path_input = QLineEdit(self.share_data.get('path', ''))
        self.path_btn = QPushButton("Seleccionar")
        self.path_btn.clicked.connect(self.select_path)
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.path_btn)
        layout.addRow(QLabel("Ruta:"), path_layout)

        self.readonly_combo = QComboBox()
        self.readonly_combo.addItems(['no', 'yes'])
        self.readonly_combo.setCurrentText(self.share_data.get('read only', 'no'))
        layout.addRow(QLabel("Solo Lectura:"), self.readonly_combo)

        self.access_input = QLineEdit(self.share_data.get('valid users', ''))
        layout.addRow(QLabel("Usuarios Permitidos (ej. juan,maria):"), self.access_input)

        self.acl_input = QLineEdit(self.share_data.get('usershare_acl', 'Everyone:F' if self.is_usershare else ''))
        layout.addRow(QLabel("ACL (ej. Everyone:F):"), self.acl_input)

        self.comment_input = QLineEdit(self.share_data.get('comment', ''))
        layout.addRow(QLabel("Comentario:"), self.comment_input)

        self.type_combo = QComboBox()
        self.type_combo.addItems(['smb.conf (admin)', 'usershares (usuario)'])
        self.type_combo.setCurrentText('usershares (usuario)' if self.is_usershare else 'smb.conf (admin)')
        layout.addRow(QLabel("Tipo:"), self.type_combo)

        self.semanage_checkbox = QCheckBox("SELinux Permanente (semanage)")
        self.semanage_checkbox.setChecked(False)
        layout.addRow(QLabel("SELinux:"), self.semanage_checkbox)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addRow(self.buttons)

        self.setLayout(layout)

    def select_path(self):
        path = QFileDialog.getExistingDirectory(self, "Seleccionar Ruta", "/")
        if path:
            self.path_input.setText(path)

    def get_data(self):
        data = {
            'name': self.name_input.text(),
            'path': self.path_input.text(),
            'read only': self.readonly_combo.currentText(),
            'comment': self.comment_input.text(),
            'type': 'usershares' if self.type_combo.currentText() == 'usershares (usuario)' else 'smb.conf',
            'semanage': self.semanage_checkbox.isChecked()
        }
        if self.access_input.text():
            data['valid users'] = self.access_input.text()
        if self.acl_input.text():
            data['usershare_acl'] = self.acl_input.text()
        return data

class SambaManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = configparser.ConfigParser(interpolation=None)
        self.smb_conf_path = "/etc/samba/smb.conf"
        self.usershares_dir = "/var/lib/samba/usershares/"
        self.logs_text = QTextEdit()
        self.load_config()
        self.initUI()

    def load_config(self):
        if os.path.exists(self.smb_conf_path):
            self.config.read(self.smb_conf_path)
            self.logs_text.append(f"Configuración cargada desde {self.smb_conf_path}")
        else:
            self.config['global'] = {'workgroup': 'LUSITANIA', 'usershare path': '/var/lib/samba/usershares'}
            self.logs_text.append("No se encontró smb.conf, usando valores por defecto (workgroup=LUSITANIA).")
        
        self.usershares_config = {}
        if os.path.exists(self.usershares_dir):
            for filename in os.listdir(self.usershares_dir):
                filepath = os.path.join(self.usershares_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        lines = f.readlines()
                        share_data = {}
                        for line in lines:
                            line = line.strip()
                            if line.startswith('#') or not line or '=' not in line:
                                continue
                            key, value = line.split('=', 1)
                            share_data[key] = value
                        if 'sharename' in share_data:
                            self.usershares_config[share_data['sharename']] = share_data
                except Exception as e:
                    self.logs_text.append(f"Error al leer {filepath}: {e}")

    def save_config(self):
        try:
            with open(self.smb_conf_path, 'w') as f:
                self.config.write(f)
            subprocess.run(["sudo", "testparm", "-s"], check=True)
            self.logs_text.append("Configuración smb.conf guardada.")
        except Exception as e:
            self.logs_text.append(f"Error al guardar smb.conf: {e}")

    def save_usershare(self, name, data):
        try:
            os.makedirs(self.usershares_dir, exist_ok=True)
            filepath = os.path.join(self.usershares_dir, name.lower())
            with open(filepath, 'w') as f:
                f.write("#VERSION 2\n")
                f.write(f"path={data['path']}\n")
                f.write(f"comment={data['comment']}\n")
                f.write(f"usershare_acl={data.get('usershare_acl', 'Everyone:F')}\n")
                f.write("guest_ok=y\n" if 'guest ok' in data else "guest_ok=n\n")
                f.write(f"sharename={name}\n")
            subprocess.run(["sudo", "chown", "root:sambashare", self.usershares_dir], check=True)
            subprocess.run(["sudo", "chmod", "1770", self.usershares_dir], check=True)
            if data.get('semanage', False):
                subprocess.run(["sudo", "semanage", "fcontext", "-a", "-t", "samba_share_t", f"{data['path']}(/.*)?"], check=True)
                subprocess.run(["sudo", "restorecon", "-R", data['path']], check=True)
                self.logs_text.append(f"SELinux permanente (semanage) aplicado a {data['path']}.")
            else:
                subprocess.run(["sudo", "chcon", "-t", "samba_share_t", data['path']], check=True)
                self.logs_text.append(f"SELinux temporal (chcon) aplicado a {data['path']}.")
            self.logs_text.append(f"Compartido '{name}' guardado en {filepath}.")
        except Exception as e:
            self.logs_text.append(f"Error al guardar usershare: {e}")

    def set_permissions(self, path, use_semanage=False):
        try:
            subprocess.run(["sudo", "chmod", "-R", "755", path], check=True)
            subprocess.run(["sudo", "chown", f"{os.getlogin()}:sambashare", path], check=True)
            if use_semanage:
                subprocess.run(["sudo", "semanage", "fcontext", "-a", "-t", "samba_share_t", f"{path}(/.*)?"], check=True)
                subprocess.run(["sudo", "restorecon", "-R", path], check=True)
                self.logs_text.append(f"SELinux permanente (semanage) aplicado a {path}.")
            else:
                subprocess.run(["sudo", "chcon", "-t", "samba_share_t", path], check=True)
                self.logs_text.append(f"SELinux temporal (chcon) aplicado a {path}.")
            self.logs_text.append(f"Permisos y SELinux ajustados para {path}.")
        except subprocess.CalledProcessError as e:
            self.logs_text.append(f"Error al ajustar permisos: {e.stderr}")

    def initUI(self):
        self.setWindowTitle("Samba Manager (Fedora)")
        self.setGeometry(100, 100, 900, 600)

        main_layout = QVBoxLayout()
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Pestaña General
        self.general_tab = QWidget()
        self.tabs.addTab(self.general_tab, "General")
        self.general_layout = QFormLayout()
        self.general_tab.setLayout(self.general_layout)

        self.workgroup_input = QLineEdit(self.config.get('global', 'workgroup', fallback='LUSITANIA'))
        self.general_layout.addRow(QLabel("Workgroup:"), self.workgroup_input)

        self.netbios_input = QLineEdit(self.config.get('global', 'netbios name', fallback='lince'))
        self.general_layout.addRow(QLabel("NetBIOS Name:"), self.netbios_input)

        self.security_combo = QComboBox()
        self.security_combo.addItems(['user', 'share'])
        self.security_combo.setCurrentText(self.config.get('global', 'security', fallback='user'))
        self.general_layout.addRow(QLabel("Security:"), self.security_combo)

        self.guest_input = QLineEdit(self.config.get('global', 'guest account', fallback='nobody'))
        self.general_layout.addRow(QLabel("Guest Account:"), self.guest_input)

        self.loglevel_combo = QComboBox()
        self.loglevel_combo.addItems(['0', '1', '2', '3'])
        self.loglevel_combo.setCurrentText(self.config.get('global', 'log level', fallback='1'))
        self.general_layout.addRow(QLabel("Log Level:"), self.loglevel_combo)

        self.usershare_path_input = QLineEdit(self.config.get('global', 'usershare path', fallback='/var/lib/samba/usershares'))
        self.general_layout.addRow(QLabel("Usershare Path:"), self.usershare_path_input)

        self.usershare_max_input = QLineEdit(self.config.get('global', 'usershare max shares', fallback='100'))
        self.general_layout.addRow(QLabel("Usershare Max Shares:"), self.usershare_max_input)

        self.usershare_guests_combo = QComboBox()
        self.usershare_guests_combo.addItems(['yes', 'no'])
        self.usershare_guests_combo.setCurrentText(self.config.get('global', 'usershare allow guests', fallback='yes'))
        self.general_layout.addRow(QLabel("Usershare Allow Guests:"), self.usershare_guests_combo)

        # Pestaña Compartidos
        self.shares_tab = QWidget()
        self.tabs.addTab(self.shares_tab, "Compartidos")
        self.shares_layout = QVBoxLayout()
        self.shares_tab.setLayout(self.shares_layout)

        self.shares_table = QTableWidget()
        self.shares_table.setColumnCount(6)
        self.shares_table.setHorizontalHeaderLabels(["Nombre", "Ruta", "Solo Lectura", "Acceso", "ACL", "Tipo"])
        self.load_shares()
        self.shares_layout.addWidget(self.shares_table)

        shares_btn_layout = QHBoxLayout()
        self.add_share_btn = QPushButton("Añadir Compartido")
        self.add_share_btn.clicked.connect(self.add_share)
        self.edit_share_btn = QPushButton("Editar")
        self.edit_share_btn.clicked.connect(self.edit_share)
        self.delete_share_btn = QPushButton("Eliminar")
        self.delete_share_btn.clicked.connect(self.delete_share)
        shares_btn_layout.addWidget(self.add_share_btn)
        shares_btn_layout.addWidget(self.edit_share_btn)
        shares_btn_layout.addWidget(self.delete_share_btn)
        self.shares_layout.addLayout(shares_btn_layout)

        # Pestaña Impresoras
        self.printers_tab = QWidget()
        self.tabs.addTab(self.printers_tab, "Impresoras")
        self.printers_layout = QVBoxLayout()
        self.printers_tab.setLayout(self.printers_layout)

        self.printers_table = QTableWidget()
        self.printers_table.setColumnCount(3)
        self.printers_table.setHorizontalHeaderLabels(["Nombre", "Ruta", "Comentario"])
        self.load_printers()
        self.printers_layout.addWidget(self.printers_table)

        printers_btn_layout = QHBoxLayout()
        self.add_printer_btn = QPushButton("Añadir Impresora")
        self.add_printer_btn.clicked.connect(self.add_printer)
        self.edit_printer_btn = QPushButton("Editar")
        self.edit_printer_btn.clicked.connect(self.edit_printer)
        self.delete_printer_btn = QPushButton("Eliminar")
        self.delete_printer_btn.clicked.connect(self.delete_printer)
        printers_btn_layout.addWidget(self.add_printer_btn)
        printers_btn_layout.addWidget(self.edit_printer_btn)
        printers_btn_layout.addWidget(self.delete_printer_btn)
        self.printers_layout.addLayout(printers_btn_layout)

        # Pestaña Usuarios
        self.users_tab = QWidget()
        self.tabs.addTab(self.users_tab, "Usuarios")
        self.users_layout = QVBoxLayout()
        self.users_tab.setLayout(self.users_layout)

        self.users_table = QTableWidget()
        self.users_table.setColumnCount(1)
        self.users_table.setHorizontalHeaderLabels(["Usuario"])
        self.load_users()
        self.users_layout.addWidget(self.users_table)

        users_btn_layout = QHBoxLayout()
        self.add_user_btn = QPushButton("Añadir Usuario")
        self.add_user_btn.clicked.connect(self.add_user)
        self.edit_user_btn = QPushButton("Editar Usuario")
        self.edit_user_btn.clicked.connect(self.edit_user)
        self.delete_user_btn = QPushButton("Eliminar Usuario")
        self.delete_user_btn.clicked.connect(self.delete_user)
        users_btn_layout.addWidget(self.add_user_btn)
        users_btn_layout.addWidget(self.edit_user_btn)
        users_btn_layout.addWidget(self.delete_user_btn)
        self.users_layout.addLayout(users_btn_layout)

        # Pestaña Logs
        self.logs_tab = QWidget()
        self.tabs.addTab(self.logs_tab, "Logs")
        self.logs_layout = QVBoxLayout()
        self.logs_tab.setLayout(self.logs_layout)
        self.logs_text.setReadOnly(True)
        self.logs_layout.addWidget(self.logs_text)

        # Botones inferiores
        self.bottom_layout = QHBoxLayout()
        self.restart_btn = QPushButton("Reiniciar Servicios")
        self.restart_btn.clicked.connect(self.restart_services)
        self.bottom_layout.addWidget(self.restart_btn)

        self.apply_btn = QPushButton("Aplicar Cambios")
        self.apply_btn.clicked.connect(self.apply_changes)
        self.bottom_layout.addWidget(self.apply_btn)

        main_layout.addLayout(self.bottom_layout)

    def load_shares(self):
        self.shares_table.setRowCount(0)
        for section in self.config.sections():
            if section != 'global' and 'print' not in section.lower() and self.config.get(section, 'printable', fallback='no') != 'yes':
                path = self.config.get(section, 'path', fallback='N/A')
                readonly = self.config.get(section, 'read only', fallback='no')
                access = self.config.get(section, 'valid users', fallback='')
                acl = self.config.get(section, 'usershare_acl', fallback='')
                row = self.shares_table.rowCount()
                self.shares_table.insertRow(row)
                self.shares_table.setItem(row, 0, QTableWidgetItem(section))
                self.shares_table.setItem(row, 1, QTableWidgetItem(path))
                self.shares_table.setItem(row, 2, QTableWidgetItem(readonly))
                self.shares_table.setItem(row, 3, QTableWidgetItem(access))
                self.shares_table.setItem(row, 4, QTableWidgetItem(acl))
                self.shares_table.setItem(row, 5, QTableWidgetItem("smb.conf"))
        
        for name, share_data in self.usershares_config.items():
            if 'print' not in name.lower() and share_data.get('printable', 'no') != 'yes':
                path = share_data.get('path', 'N/A')
                readonly = 'no' if share_data.get('guest_ok', 'n') == 'y' else 'yes'
                access = share_data.get('valid users', '')
                acl = share_data.get('usershare_acl', '')
                row = self.shares_table.rowCount()
                self.shares_table.insertRow(row)
                self.shares_table.setItem(row, 0, QTableWidgetItem(name))
                self.shares_table.setItem(row, 1, QTableWidgetItem(path))
                self.shares_table.setItem(row, 2, QTableWidgetItem(readonly))
                self.shares_table.setItem(row, 3, QTableWidgetItem(access))
                self.shares_table.setItem(row, 4, QTableWidgetItem(acl))
                self.shares_table.setItem(row, 5, QTableWidgetItem("usershares"))

    def add_share(self):
        dialog = ShareDialog(self)
        if dialog.exec_():
            data = dialog.get_data()
            if not data['name']:
                QMessageBox.warning(self, "Error", "El nombre del compartido no puede estar vacío.")
                return
            share_config = {
                'path': data['path'],
                'read only': data['read only'],
                'comment': data['comment']
            }
            if data.get('valid users'):
                share_config['valid users'] = data['valid users']
            else:
                share_config['guest ok'] = 'yes'
            if data.get('usershare_acl'):
                share_config['usershare_acl'] = data['usershare_acl']

            if data['type'] == 'smb.conf':
                self.config[data['name']] = share_config
                self.save_config()
            else:
                self.usershares_config[data['name']] = share_config
                self.save_usershare(data['name'], share_config)
            self.set_permissions(data['path'], use_semanage=data.get('semanage', False))
            self.load_shares()

    def edit_share(self):
        selected = self.shares_table.currentRow()
        if selected >= 0:
            name = self.shares_table.item(selected, 0).text()
            source = self.shares_table.item(selected, 5).text()
            config = self.config if source == "smb.conf" else self.usershares_config
            dialog = ShareDialog(self, name, config[name], source == "usershares")
            if dialog.exec_():
                data = dialog.get_data()
                share_config = {
                    'path': data['path'],
                    'read only': data['read only'],
                    'comment': data['comment']
                }
                if data.get('valid users'):
                    share_config['valid users'] = data['valid users']
                    if 'guest ok' in config[name]:
                        del config[name]['guest ok']
                else:
                    share_config['guest ok'] = 'yes'
                    if 'valid users' in config[name]:
                        del config[name]['valid users']
                if data.get('usershare_acl'):
                    share_config['usershare_acl'] = data['usershare_acl']
                elif 'usershare_acl' in config[name]:
                    del config[name]['usershare_acl']

                if data['type'] == 'smb.conf':
                    if source == "usershares":
                        del self.usershares_config[name]
                        os.remove(os.path.join(self.usershares_dir, name.lower()))
                    self.config[data['name']] = share_config
                    self.save_config()
                else:
                    if source == "smb.conf":
                        self.config.remove_section(name)
                    self.usershares_config[data['name']] = share_config
                    self.save_usershare(data['name'], share_config)
                self.set_permissions(data['path'], use_semanage=data.get('semanage', False))
                self.load_shares()
        else:
            QMessageBox.warning(self, "Error", "Selecciona un compartido para editar.")

    def delete_share(self):
        selected = self.shares_table.currentRow()
        if selected >= 0:
            name = self.shares_table.item(selected, 0).text()
            source = self.shares_table.item(selected, 5).text()
            path = self.shares_table.item(selected, 1).text()
            reply = QMessageBox.question(self, 'Confirmar eliminación', 
                                        f"¿Estás seguro de eliminar el compartido '{name}'?",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    if source == "smb.conf":
                        self.config.remove_section(name)
                        self.save_config()
                    elif source == "usershares":
                        del self.usershares_config[name]
                        os.remove(os.path.join(self.usershares_dir, name.lower()))
                    
                    if path and os.path.exists(path):
                        subprocess.run(["sudo", "restorecon", "-R", path], check=True)
                        self.logs_text.append(f"Contexto SELinux restaurado para {path}.")
                    else:
                        self.logs_text.append(f"No se restauró SELinux: {path} no existe o no está definido.")
                    
                    self.load_shares()
                except subprocess.CalledProcessError as e:
                    self.logs_text.append(f"Error al eliminar compartido o restaurar SELinux: {e.stderr}")
                except Exception as e:
                    self.logs_text.append(f"Error inesperado al eliminar compartido: {e}")
        else:
            QMessageBox.warning(self, "Error", "Selecciona un compartido para eliminar.")

    def load_printers(self):
        self.printers_table.setRowCount(0)
        for section in self.config.sections():
            if 'print' in section.lower() or self.config.get(section, 'printable', fallback='no') == 'yes':
                path = self.config.get(section, 'path', fallback='N/A')
                comment = self.config.get(section, 'comment', fallback='')
                row = self.printers_table.rowCount()
                self.printers_table.insertRow(row)
                self.printers_table.setItem(row, 0, QTableWidgetItem(section))
                self.printers_table.setItem(row, 1, QTableWidgetItem(path))
                self.printers_table.setItem(row, 2, QTableWidgetItem(comment))

    def add_printer(self):
        from PyQt5.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "Añadir Impresora", "Nombre de la impresora:")
        if ok and name:
            printer_config = {
                'printable': 'yes',
                'path': '/var/spool/samba',
                'comment': f'Impresora {name}',
                'guest ok': 'yes'
            }
            self.config[name] = printer_config
            self.save_config()
            self.load_printers()

    def edit_printer(self):
        selected = self.printers_table.currentRow()
        if selected >= 0:
            name = self.printers_table.item(selected, 0).text()
            dialog = ShareDialog(self, name, self.config[name])
            if dialog.exec_():
                data = dialog.get_data()
                printer_config = {
                    'printable': 'yes',
                    'path': data['path'],
                    'comment': data['comment']
                }
                if data.get('valid users'):
                    printer_config['valid users'] = data['valid users']
                else:
                    printer_config['guest ok'] = 'yes'
                self.config[data['name']] = printer_config
                self.save_config()
                self.load_printers()
        else:
            QMessageBox.warning(self, "Error", "Selecciona una impresora para editar.")

    def delete_printer(self):
        selected = self.printers_table.currentRow()
        if selected >= 0:
            name = self.printers_table.item(selected, 0).text()
            reply = QMessageBox.question(self, 'Confirmar eliminación', 
                                        f"¿Estás seguro de eliminar la impresora '{name}'?",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.config.remove_section(name)
                self.save_config()
                self.load_printers()
        else:
            QMessageBox.warning(self, "Error", "Selecciona una impresora para eliminar.")

    def load_users(self):
        self.users_table.setRowCount(0)
        try:
            result = subprocess.run(["pdbedit", "-L"], capture_output=True, text=True, check=True)
            users = result.stdout.splitlines()
            for user in users:
                username = user.split(':')[0]
                row = self.users_table.rowCount()
                self.users_table.insertRow(row)
                self.users_table.setItem(row, 0, QTableWidgetItem(username))
        except subprocess.CalledProcessError as e:
            self.logs_text.append(f"Error al listar usuarios: {e.stderr}")

    def add_user(self):
        from PyQt5.QtWidgets import QInputDialog, QLineEdit
        username, ok = QInputDialog.getText(self, "Añadir Usuario", "Nombre de usuario:")
        if ok and username:
            password, ok = QInputDialog.getText(self, "Contraseña", "Contraseña para el usuario:", QLineEdit.Password)
            if ok and password:
                try:
                    subprocess.run(["sudo", "smbpasswd", "-a", username], input=password, text=True, check=True)
                    self.logs_text.append(f"Usuario '{username}' añadido.")
                    self.load_users()
                except subprocess.CalledProcessError as e:
                    self.logs_text.append(f"Error al añadir usuario: {e.stderr}")

    def edit_user(self):
        selected = self.users_table.currentRow()
        if selected >= 0:
            username = self.users_table.item(selected, 0).text()
            from PyQt5.QtWidgets import QInputDialog, QLineEdit
            new_password, ok = QInputDialog.getText(self, "Editar Usuario", 
                                                   f"Nueva contraseña para {username}:", 
                                                   QLineEdit.Password)
            if ok and new_password:
                try:
                    subprocess.run(["sudo", "smbpasswd", username], 
                                 input=new_password, text=True, check=True)
                    self.logs_text.append(f"Contraseña de '{username}' actualizada.")
                except subprocess.CalledProcessError as e:
                    self.logs_text.append(f"Error al editar usuario: {e.stderr}")
        else:
            QMessageBox.warning(self, "Error", "Selecciona un usuario para editar.")

    def delete_user(self):
        selected = self.users_table.currentRow()
        if selected >= 0:
            username = self.users_table.item(selected, 0).text()
            reply = QMessageBox.question(self, 'Confirmar eliminación', 
                                        f"¿Estás seguro de eliminar el usuario '{username}'?",
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    subprocess.run(["sudo", "smbpasswd", "-x", username], check=True)
                    self.logs_text.append(f"Usuario '{username}' eliminado.")
                    self.load_users()
                except subprocess.CalledProcessError as e:
                    self.logs_text.append(f"Error al eliminar usuario: {e.stderr}")

    def restart_services(self):
        try:
            subprocess.run(["sudo", "systemctl", "restart", "smb"], check=True)
            subprocess.run(["sudo", "systemctl", "restart", "nmb"], check=True)
            self.logs_text.append("Servicios smb y nmb reiniciados con éxito.")
        except subprocess.CalledProcessError as e:
            self.logs_text.append(f"Error al reiniciar servicios: {e.stderr}")

    def apply_changes(self):
        reply = QMessageBox.question(self, 'Confirmar cambios', 
                                    "¿Estás seguro de aplicar los cambios?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.config.set('global', 'workgroup', self.workgroup_input.text())
            self.config.set('global', 'netbios name', self.netbios_input.text())
            self.config.set('global', 'security', self.security_combo.currentText())
            self.config.set('global', 'guest account', self.guest_input.text())
            self.config.set('global', 'log level', self.loglevel_combo.currentText())
            self.config.set('global', 'usershare path', self.usershare_path_input.text())
            self.config.set('global', 'usershare max shares', self.usershare_max_input.text())
            self.config.set('global', 'usershare allow guests', self.usershare_guests_combo.currentText())
            self.config.set('global', 'local master', 'yes')
            self.config.set('global', 'preferred master', 'yes')
            self.config.set('global', 'os level', '65')
            self.save_config()
            self.restart_services()

def main():
    app = QApplication(sys.argv)
    ex = SambaManager()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
