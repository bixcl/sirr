import sys
import os
import json
import base64
import hashlib
import random
import string
import math
import binascii
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QCheckBox, 
                            QComboBox, QTextEdit, QTableWidget, QTableWidgetItem, 
                            QHeaderView, QSlider, QMessageBox, QGroupBox, QFormLayout,
                            QSpacerItem, QSizePolicy, QDialog, QDialogButtonBox)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor, QIcon, QPalette

# Import crypto modules from PyCryptodome (same as in original)
from Crypto.Cipher import DES, DES3, ARC4, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Helper function for getting resource paths when running as an executable
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    
    return os.path.join(base_path, relative_path)

# File paths
CREDENTIALS_FILE = resource_path("credentials.json")
PASSWORD_STORE_FILE = resource_path("password_store.json")

# Global variables for login
admin_username = "admin"
admin_password = "admin"

# ===================== UTILITY FUNCTIONS ======================
# Hash password using SHA-256
def hash_password(password):
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.sha256(password).hexdigest()

# Save credentials to file with password hashing
def save_credentials(username, password):
    try:
        # Use the global credential file path
        credentials_path = CREDENTIALS_FILE
        
        # Hash the password if it's not already hashed
        if isinstance(password, str) and len(password) != 64:  # SHA-256 produces 64 hex chars
            hashed_password = hash_password(password)
        else:
            hashed_password = password
            
        with open(credentials_path, 'w') as f:
            json.dump({'username': username, 'password': hashed_password}, f)
            
        print(f"Credentials saved successfully to {credentials_path}")
        return True
    except Exception as e:
        print(f"Error saving credentials: {e}")
        return False

# Load saved credentials if they exist
def load_credentials():
    global admin_username, admin_password
    try:
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, 'r') as f:
                creds = json.load(f)
                admin_username = creds.get('username', admin_username)
                # Store the password hash directly (it's already hashed in the file)
                admin_password = creds.get('password', hash_password(admin_password))
        else:
            # If no credentials file exists, hash the default password
            admin_password = hash_password(admin_password)
    except Exception as e:
        # If there's any error, make sure the default password is hashed
        admin_password = hash_password(admin_password)
        print(f"Error loading credentials: {e}")

# Password store functions
def save_password(site, username, password):
    passwords = {}
    if os.path.exists(PASSWORD_STORE_FILE):
        try:
            with open(PASSWORD_STORE_FILE, 'r') as f:
                passwords = json.load(f)
        except:
            passwords = {}
    
    # Encrypt both username and password before saving
    encrypted_pwd = encrypt_password(password)
    encrypted_user = encrypt_password(username)
    
    if site not in passwords:
        passwords[site] = []
    passwords[site].append({"username": encrypted_user, "password": encrypted_pwd})
    
    with open(PASSWORD_STORE_FILE, 'w') as f:
        json.dump(passwords, f)
    
    return True

def encrypt_password(password):
    # Use 3DES with a fixed key for better security
    key = b"SecurityKey123".ljust(24, b'\0')[:24]  # 3DES requires 24 bytes key
    return base64.b64encode(encrypt_3des(password, key)).decode('utf-8')

def decrypt_password(encrypted):
    # Use 3DES with a fixed key for better security (same key used for encryption)
    key = b"SecurityKey123".ljust(24, b'\0')[:24]  # 3DES requires 24 bytes key
    try:
        encrypted_bytes = base64.b64decode(encrypted)
        return decrypt_3des(encrypted_bytes, key)
    except:
        return "Error decrypting"

def load_passwords():
    if not os.path.exists(PASSWORD_STORE_FILE):
        return {}
    try:
        with open(PASSWORD_STORE_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def delete_password(site, encrypted_username):
    passwords = load_passwords()
    if site in passwords:
        # Filter out the entry with the matching encrypted username
        passwords[site] = [entry for entry in passwords[site] if entry["username"] != encrypted_username]
        if not passwords[site]:
            del passwords[site]
        
        with open(PASSWORD_STORE_FILE, 'w') as f:
            json.dump(passwords, f)
        
        return True
    return False

# ===================== ENCRYPTION ALGORITHMS ======================
# Helper functions for encryption algorithms
def encrypt_des(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    # Ensure key is correct length
    key = key[:8].ljust(8, b'\0')
    cipher = DES.new(key, DES.MODE_ECB)
    if isinstance(data, str):
        data = data.encode('utf-8')
    return cipher.encrypt(pad(data, DES.block_size))

def decrypt_des(data, key, raw=False):
    if isinstance(key, str):
        key = key.encode('utf-8')
    # Ensure key is correct length
    key = key[:8].ljust(8, b'\0')
    cipher = DES.new(key, DES.MODE_ECB)
    result = unpad(cipher.decrypt(data), DES.block_size)
    if raw:
        return result
    return result.decode('utf-8', errors='ignore')

def encrypt_3des(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    # 3DES requires a 24-byte key
    key = key.ljust(24, b'\0')[:24]
    cipher = DES3.new(key, DES3.MODE_ECB)
    if isinstance(data, str):
        data = data.encode('utf-8')
    return cipher.encrypt(pad(data, DES3.block_size))

def decrypt_3des(data, key, raw=False):
    if isinstance(key, str):
        key = key.encode('utf-8')
    # 3DES requires a 24-byte key
    key = key.ljust(24, b'\0')[:24]
    cipher = DES3.new(key, DES3.MODE_ECB)
    result = unpad(cipher.decrypt(data), DES3.block_size)
    if raw:
        return result
    return result.decode('utf-8', errors='ignore')

def encrypt_rc4(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = ARC4.new(key)
    if isinstance(data, str):
        data = data.encode('utf-8')
    return cipher.encrypt(data)

def decrypt_rc4(data, key, raw=False):
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = ARC4.new(key)
    result = cipher.decrypt(data)
    if raw:
        return result
    return result.decode('utf-8', errors='ignore')

def encrypt_caesar(data, key):
    if isinstance(key, str):
        try:
            key = int(key) % 26
        except:
            key = len(key) % 26
    else:
        key = int(key) % 26
        
    result = ""
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    
    for char in data:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + key) % 26 + ascii_offset)
        else:
            result += char
    return result  # Return string directly, not encoded bytes

def decrypt_caesar(data, key):
    if isinstance(data, bytes):
        try:
            # Try to decode base64 first
            text = base64.b64decode(data).decode('utf-8', errors='ignore')
        except:
            # If not base64, try to decode directly
            text = data.decode('utf-8', errors='ignore')
    else:
        text = data
        
    if isinstance(key, str):
        try:
            key = int(key) % 26
        except:
            key = len(key) % 26
    else:
        key = int(key) % 26
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset - key) % 26 + ascii_offset)
        else:
            result += char
    
    return result

def encrypt_substitution(data, key):
    if isinstance(key, str):
        key = key.lower()
    else:
        key = "secretkey"
    
    # Create substitution map based on key
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    substitution_map = {}
    seed_key = sum(ord(c) for c in key)
    random.seed(seed_key)
    shuffled = list(alphabet)
    random.shuffle(shuffled)
    for i in range(len(alphabet)):
        substitution_map[alphabet[i]] = shuffled[i]
        substitution_map[alphabet[i].upper()] = shuffled[i].upper()
    
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    
    result = ""
    for char in data:
        if char.isalpha():
            result += substitution_map.get(char, char)
        else:
            result += char
    return result.encode('utf-8')

def decrypt_substitution(data, key, raw=False):
    # For simplicity, we use the same key-based approach
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    
    if isinstance(key, str):
        key = key.lower()
    else:
        key = "secretkey"
    
    # Create reverse substitution map
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    substitution_map = {}
    seed_key = sum(ord(c) for c in key)
    random.seed(seed_key)
    shuffled = list(alphabet)
    random.shuffle(shuffled)
    for i in range(len(alphabet)):
        substitution_map[shuffled[i]] = alphabet[i]
        substitution_map[shuffled[i].upper()] = alphabet[i].upper()
    
    result = ""
    for char in data:
        if char.isalpha():
            result += substitution_map.get(char, char)
        else:
            result += char
    
    if raw:
        return result.encode('utf-8')
    return result

def encrypt_blowfish(data, key):
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    if isinstance(data, str):
        data = data.encode('utf-8')
    return cipher.encrypt(pad(data, Blowfish.block_size))

def decrypt_blowfish(data, key, raw=False):
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    result = unpad(cipher.decrypt(data), Blowfish.block_size)
    if raw:
        return result
    return result.decode('utf-8', errors='ignore')

# Encryption dispatcher functions
def encrypt_data(data, algorithm, key):
    encryption_functions = {
        "DES": encrypt_des,
        "3DES": encrypt_3des,
        "RC4": encrypt_rc4,
        "Caesar Cipher": encrypt_caesar,
        "Substitution": encrypt_substitution,
        "Blowfish": encrypt_blowfish
    }
    
    if algorithm not in encryption_functions:
        return f"Unknown algorithm: {algorithm}"
    
    try:
        return encryption_functions[algorithm](data, key)
    except Exception as e:
        return f"Encryption error: {str(e)}"

def decrypt_data(data, algorithm, key):
    decryption_functions = {
        "DES": decrypt_des,
        "3DES": decrypt_3des,
        "RC4": decrypt_rc4,
        "Caesar Cipher": decrypt_caesar,
        "Substitution": decrypt_substitution,
        "Blowfish": decrypt_blowfish
    }
    
    if algorithm not in decryption_functions:
        return f"Unknown algorithm: {algorithm}"
    
    try:
        return decryption_functions[algorithm](data, key)
    except UnicodeDecodeError:
        # Handle UTF-8 decoding errors gracefully
        result_bytes = decryption_functions[algorithm](data, key, raw=True)
        if isinstance(result_bytes, bytes):
            # Try Latin-1 which can encode any byte value
            return result_bytes.decode('latin-1', errors='replace')
        return "Decryption resulted in non-text data"
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Generate a secure password
def generate_password(length, complexity):
    chars = string.ascii_letters
    if complexity > 1:
        chars += string.digits
    if complexity > 2:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Function to detect algorithm
def identify_cipher_type(data):
    try:
        # Try to decode base64 first
        try:
            decoded = base64.b64decode(data)
            base64_successful = True
        except:
            decoded = data if isinstance(data, bytes) else data.encode('utf-8')
            base64_successful = False
        
        # Check data characteristics
        characteristics = {
            "DES": 0,
            "3DES": 0,
            "RC4": 0,
            "Blowfish": 0,
            "Caesar Cipher": 0,
            "Substitution": 0
        }
        
        # If base64 decoding was successful, it's likely a binary encryption method
        if base64_successful:
            # Caesar cipher doesn't typically use base64
            characteristics["Caesar Cipher"] -= 10
            characteristics["Substitution"] -= 5
            
            # These algorithms typically output binary data encoded in base64
            characteristics["DES"] += 3
            characteristics["3DES"] += 3
            characteristics["RC4"] += 4
            characteristics["Blowfish"] += 3
            
        # Additional detection logic (simplified version)
        data_len = len(decoded)
        
        # Check the data length and other characteristics
        if data_len % 8 == 0:  # Block size for DES, 3DES, Blowfish
            characteristics["DES"] += 2
            characteristics["3DES"] += 2
            characteristics["Blowfish"] += 2
            
            if data_len > 24:
                characteristics["3DES"] += 2
            elif data_len > 16:
                characteristics["Blowfish"] += 2
            else:
                characteristics["DES"] += 2
                
        # Check if it looks like text (could be Caesar)
        if isinstance(data, str):
            if all(c.isprintable() for c in data):
                characteristics["Caesar Cipher"] += 5
                characteristics["Substitution"] += 2
        
        # Find most likely algorithm
        most_likely = max(characteristics.items(), key=lambda x: x[1])
        return most_likely[0], characteristics
    
    except Exception as e:
        print(f"Error in cipher detection: {e}")
        return "Unknown", {"error": str(e)}

# Get algorithm info
def get_algorithm_info(algorithm):
    algo_info = {
        "DES": "Block cipher with 8-byte key. Requires key and uses padding.",
        "3DES": "Triple DES uses 24-byte key. More secure than DES.",
        "RC4": "Stream cipher with variable key length. No padding required.",
        "Caesar Cipher": "Simple substitution cipher. Key is a number (shift value).",
        "Substitution": "Character substitution based on key's hash. Use any text key.",
        "Blowfish": "Block cipher with variable key length. Requires padding."
    }
    return algo_info.get(algorithm, "No information available")

# ===================== LOGIN DIALOG ======================
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sirr | سر - Login")
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        # Set the style
        self.setStyleSheet("""
            QDialog { 
                background-color: #1e1e2e;
                border-radius: 10px;
            }
            QLabel { 
                color: #cdd6f4;
                font-size: 12px;
            }
            QLineEdit {
                padding: 8px;
                border-radius: 4px;
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
            }
            QPushButton {
                padding: 10px;
                font-weight: bold;
                border-radius: 4px;
                background-color: #7b68ee;
                color: white;
                border: none;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        
        # Add a title
        title_label = QLabel("Sirr | سر")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 20px; color: #7b68ee; margin-bottom: 15px; font-weight: bold;")
        self.layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.layout.addWidget(title_label)
        
        # Create label for welcome
        welcome_label = QLabel("Welcome back! Please login to continue.")
        welcome_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(welcome_label)
        self.layout.addItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Minimum))
        
        # Create form layout for inputs
        form_layout = QFormLayout()
        
        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        form_layout.addRow("Username:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your password")
        form_layout.addRow("Password:", self.password_input)
        
        # Add form to main layout
        self.layout.addLayout(form_layout)
        self.layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Minimum))
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setFixedHeight(40)
        self.login_button.clicked.connect(self.verify_login)
        self.layout.addWidget(self.login_button)
        
        # Register button
        self.register_button = QPushButton("Register")
        self.register_button.setFixedHeight(40)
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #45475a;
                color: white;
                padding: 10px;
                font-weight: bold;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover {
                background-color: #585b70;
            }
        """)
        self.register_button.clicked.connect(self.show_register_dialog)
        self.layout.addWidget(self.register_button)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #f38ba8;") # Red for errors
        self.layout.addWidget(self.status_label)
        
        self.layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        # Load saved credentials
        load_credentials()
        
        self.success = False
    
    def verify_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        # Hash the entered password and compare with stored hash
        hashed_input = hash_password(password)
        
        if username == admin_username and hashed_input == admin_password:
            self.success = True
            self.accept()
        else:
            self.status_label.setText("Invalid username or password!")
    
    def show_register_dialog(self):
        register_dialog = RegisterDialog(self)
        if register_dialog.exec_() == QDialog.Accepted:
            self.status_label.setText("Registration successful! You can now login.")
            self.status_label.setStyleSheet("color: #a6e3a1;") # Green for success
            
    def get_success(self):
        return self.success

# ===================== REGISTER DIALOG ======================
class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sirr | سر - Register")
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        # Set the style
        self.setStyleSheet("""
            QDialog { 
                background-color: #1e1e2e;
                border-radius: 10px;
            }
            QLabel { 
                color: #cdd6f4;
                font-size: 12px;
            }
            QLineEdit {
                padding: 8px;
                border-radius: 4px;
                background-color: #313244;
                color: #cdd6f4;
                border: 1px solid #45475a;
            }
            QPushButton {
                padding: 10px;
                font-weight: bold;
                border-radius: 4px;
                background-color: #7b68ee;
                color: white;
                border: none;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        
        # Add a title
        title_label = QLabel("Sirr | سر")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 20px; color: #7b68ee; margin-bottom: 15px; font-weight: bold;")
        self.layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        self.layout.addWidget(title_label)
        
        # Create label for welcome
        welcome_label = QLabel("Create a new account")
        welcome_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(welcome_label)
        self.layout.addItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Minimum))
        
        # Create form layout for inputs
        form_layout = QFormLayout()
        
        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        form_layout.addRow("Username:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your password")
        form_layout.addRow("Password:", self.password_input)
        
        # Confirm Password
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm your password")
        form_layout.addRow("Confirm Password:", self.confirm_password_input)
        
        # Add form to main layout
        self.layout.addLayout(form_layout)
        self.layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Minimum))
        
        # Register button
        self.register_button = QPushButton("Register")
        self.register_button.setFixedHeight(40)
        self.register_button.clicked.connect(self.register_user)
        self.layout.addWidget(self.register_button)
        
        # Status message
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #f38ba8;") # Red for errors
        self.layout.addWidget(self.status_label)
        
        self.layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
    
    def register_user(self):
        username = self.username_input.text()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if not username or not password:
            self.status_label.setText("Username and password cannot be empty")
            return
            
        if password != confirm_password:
            self.status_label.setText("Passwords do not match")
            return
        
        # Save the credentials
        if save_credentials(username, password):
            global admin_username, admin_password
            admin_username = username
            admin_password = hash_password(password)
            self.accept()
        else:
            self.status_label.setText("Error saving credentials")

# ===================== MAIN APPLICATION ======================
class SecurePasswordToolkitApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Set window properties
        self.setWindowTitle("Sirr | سر")
        self.setGeometry(100, 100, 900, 700)
        
        # Create the central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create header with logout button
        header_layout = QHBoxLayout()
        
        header = QLabel("Sirr | سر")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #7b68ee; margin: 10px;")
        header_layout.addWidget(header)
        
        # Add logout button
        self.logout_button = QPushButton("Logout")
        self.logout_button.setFixedWidth(100)
        self.logout_button.setStyleSheet("""
            QPushButton {
                background-color: #f38ba8;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #eb6f92;
            }
        """)
        self.logout_button.clicked.connect(self.logout)
        header_layout.addWidget(self.logout_button)
        
        self.main_layout.addLayout(header_layout)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 10px 20px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #7b68ee;
                color: white;
            }
        """)
        
        # Create tabs
        self.setup_password_manager_tab()
        self.setup_encryption_tab()
        self.setup_decryption_tab()
        self.setup_password_generator_tab()
        
        # Add tabs to widget
        self.tabs.addTab(self.password_manager_tab, "Password Manager")
        self.tabs.addTab(self.encryption_tab, "Encryption")
        self.tabs.addTab(self.decryption_tab, "Decryption")
        self.tabs.addTab(self.password_generator_tab, "Password Generator")
        
        # Add tab widget to main layout
        self.main_layout.addWidget(self.tabs)
    
    def logout(self):
        # Show confirmation dialog
        reply = QMessageBox.question(self, 'Logout Confirmation', 
                                   'Are you sure you want to logout?', 
                                   QMessageBox.Yes | QMessageBox.No, 
                                   QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Close current window and show login dialog
            self.hide()
            login_dialog = LoginDialog()
            if login_dialog.exec_():
                # If login successful, show main window again
                if login_dialog.get_success():
                    self.show()
                else:
                    # If login cancelled or failed, close the application
                    self.close()
            else:
                # If login dialogue was closed, close the application
                self.close()
    
    # ===================== PASSWORD MANAGER TAB ======================
    def setup_password_manager_tab(self):
        self.password_manager_tab = QWidget()
        layout = QVBoxLayout(self.password_manager_tab)
        
        # Create "Add New Password" section
        add_password_group = QGroupBox("Add New Password")
        add_password_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        form_layout = QFormLayout()
        
        # Add site input
        self.pm_site = QLineEdit()
        self.pm_site.setPlaceholderText("e.g. google.com")
        form_layout.addRow("Website/Service:", self.pm_site)
        
        # Add username input
        self.pm_username = QLineEdit()
        self.pm_username.setPlaceholderText("Your username")
        form_layout.addRow("Username:", self.pm_username)
        
        # Add password input
        self.pm_password = QLineEdit()
        self.pm_password.setEchoMode(QLineEdit.Password)
        self.pm_password.setPlaceholderText("Your password")
        form_layout.addRow("Password:", self.pm_password)
        
        # Add button layout
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        save_btn = QPushButton("Save Password")
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #7b68ee;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        save_btn.clicked.connect(self.save_password_clicked)
        button_layout.addWidget(save_btn)
        button_layout.addStretch()
        
        # Add layouts to group
        add_password_layout = QVBoxLayout()
        add_password_layout.addLayout(form_layout)
        add_password_layout.addLayout(button_layout)
        add_password_group.setLayout(add_password_layout)
        
        # Add the group to main layout
        layout.addWidget(add_password_group)
        
        # Status label
        self.pm_status = QLabel("")
        self.pm_status.setAlignment(Qt.AlignCenter)
        self.pm_status.setStyleSheet("color: #a6e3a1; margin: 5px;") # Green for success
        layout.addWidget(self.pm_status)
        
        # Create "Saved Passwords" section
        saved_passwords_group = QGroupBox("Saved Passwords")
        saved_passwords_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        saved_passwords_layout = QVBoxLayout()
        
        # Add refresh button
        refresh_btn = QPushButton("Refresh List")
        refresh_btn.clicked.connect(self.refresh_passwords)
        refresh_btn.setFixedWidth(150)
        
        refresh_layout = QHBoxLayout()
        refresh_layout.addStretch()
        refresh_layout.addWidget(refresh_btn)
        saved_passwords_layout.addLayout(refresh_layout)
        
        # Create table for passwords
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(4)
        self.password_table.setHorizontalHeaderLabels(["Site", "Username", "Password", "Actions"])
        self.password_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.password_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.password_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.password_table.verticalHeader().setVisible(False)
        
        # Add table to layout
        saved_passwords_layout.addWidget(self.password_table)
        saved_passwords_group.setLayout(saved_passwords_layout)
        
        # Add to main layout
        layout.addWidget(saved_passwords_group)
        
        # Load initial passwords
        self.refresh_passwords()
    
    def save_password_clicked(self):
        site = self.pm_site.text()
        username = self.pm_username.text()
        password = self.pm_password.text()
        
        if not site or not username or not password:
            self.pm_status.setText("Please fill in all fields")
            self.pm_status.setStyleSheet("color: #f38ba8;")  # Red for errors
            return
            
        if save_password(site, username, password):
            self.pm_status.setText(f"Password saved for {site}")
            self.pm_status.setStyleSheet("color: #a6e3a1;")  # Green for success
            
            # Clear inputs
            self.pm_site.clear()
            self.pm_username.clear()
            self.pm_password.clear()
            
            # Refresh the table
            self.refresh_passwords()
        else:
            self.pm_status.setText("Error saving password")
            self.pm_status.setStyleSheet("color: #f38ba8;")  # Red for errors
    
    def refresh_passwords(self):
        # Clear the table
        self.password_table.setRowCount(0)
        
        # Load passwords
        passwords = load_passwords()
        row = 0
        
        # Populate table
        for site, entries in passwords.items():
            for entry in entries:
                # Add a new row
                self.password_table.insertRow(row)
                
                # Site
                site_item = QTableWidgetItem(site)
                site_item.setFlags(site_item.flags() & ~Qt.ItemIsEditable)
                self.password_table.setItem(row, 0, site_item)
                
                # Username (masked)
                username_item = QTableWidgetItem("********")
                username_item.setFlags(username_item.flags() & ~Qt.ItemIsEditable)
                self.password_table.setItem(row, 1, username_item)
                
                # Password (masked)
                password_item = QTableWidgetItem("********")
                password_item.setFlags(password_item.flags() & ~Qt.ItemIsEditable)
                self.password_table.setItem(row, 2, password_item)
                
                # Store the actual encrypted values
                enc_user = entry["username"]
                enc_pwd = entry["password"]
                
                # Create action buttons separated in their own cells
                actions_widget = QWidget()
                actions_widget.setStyleSheet("background-color: transparent;")
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(2, 2, 2, 2)
                actions_layout.setSpacing(12)
                
                # Show button
                show_btn = QPushButton("Show")
                show_btn.setFixedWidth(40)
                show_btn.setFixedHeight(25)
                show_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #7b68ee;
                        color: white;
                        border-radius: 3px;
                        font-size: 9px;
                        font-weight: bold;
                        margin: 0px;
                        padding: 0px;
                    }
                    QPushButton:hover {
                        background-color: #9370db;
                    }
                """)
                show_btn.clicked.connect(lambda checked, r=row, u=enc_user, p=enc_pwd: 
                                          self.toggle_show_password(r, u, p))
                
                # Copy button
                copy_btn = QPushButton("Copy")
                copy_btn.setFixedWidth(40)
                copy_btn.setFixedHeight(25)
                copy_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #7b68ee;
                        color: white;
                        border-radius: 3px;
                        font-size: 9px;
                        font-weight: bold;
                        margin: 0px;
                        padding: 0px;
                    }
                    QPushButton:hover {
                        background-color: #9370db;
                    }
                """)
                copy_btn.clicked.connect(lambda checked, p=enc_pwd: self.copy_password(p))
                
                # Delete button
                delete_btn = QPushButton("Del")
                delete_btn.setFixedWidth(40)
                delete_btn.setFixedHeight(25)
                delete_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #7b68ee;
                        color: white;
                        border-radius: 3px;
                        font-size: 9px;
                        font-weight: bold;
                        margin: 0px;
                        padding: 0px;
                    }
                    QPushButton:hover {
                        background-color: #9370db;
                    }
                """)
                delete_btn.clicked.connect(lambda checked, s=site, u=enc_user: self.delete_password_entry(s, u))
                
                # Add buttons with proper spacing
                actions_layout.addWidget(show_btn)
                actions_layout.addWidget(copy_btn)
                actions_layout.addWidget(delete_btn)
                
                self.password_table.setCellWidget(row, 3, actions_widget)
                
                row += 1
    
    def toggle_show_password(self, row, enc_username, enc_password):
        username_item = self.password_table.item(row, 1)
        password_item = self.password_table.item(row, 2)
        
        # Check if currently showing or masked
        is_showing = username_item.text() != "********"
        
        if is_showing:
            # Mask again
            username_item.setText("********")
            password_item.setText("********")
        else:
            # Show decrypted values
            username_item.setText(decrypt_password(enc_username))
            password_item.setText(decrypt_password(enc_password))
    
    def copy_password(self, enc_password):
        decrypted = decrypt_password(enc_password)
        clipboard = QApplication.clipboard()
        clipboard.setText(decrypted)
        self.pm_status.setText("Password copied to clipboard!")
        self.pm_status.setStyleSheet("color: #a6e3a1;")  # Green for success
    
    def delete_password_entry(self, site, enc_username):
        if delete_password(site, enc_username):
            self.refresh_passwords()
            self.pm_status.setText(f"Entry deleted successfully")
            self.pm_status.setStyleSheet("color: #a6e3a1;")  # Green for success
        else:
            self.pm_status.setText("Error deleting entry")
            self.pm_status.setStyleSheet("color: #f38ba8;")  # Red for errors
    
    # ===================== ENCRYPTION TAB ======================
    def setup_encryption_tab(self):
        self.encryption_tab = QWidget()
        layout = QVBoxLayout(self.encryption_tab)
        
        # Algorithm selection section
        algo_group = QGroupBox("Encryption Settings")
        algo_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        algo_layout = QVBoxLayout()
        
        # Add algorithm selection
        algo_form = QFormLayout()
        self.encryption_algo = QComboBox()
        self.encryption_algo.addItems(["DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"])
        self.encryption_algo.currentIndexChanged.connect(self.update_algorithm_info)
        algo_form.addRow("Encryption Algorithm:", self.encryption_algo)
        
        # Algorithm info
        self.algorithm_info = QLabel(get_algorithm_info("DES"))
        self.algorithm_info.setStyleSheet("color: #7f849c; font-style: italic;")
        self.algorithm_info.setWordWrap(True)
        algo_form.addRow(self.algorithm_info)
        
        # Key input
        self.encryption_key = QLineEdit()
        self.encryption_key.setPlaceholderText("Enter encryption key")
        algo_form.addRow("Encryption Key:", self.encryption_key)
        
        # Second algorithm option
        self.use_second_algo = QCheckBox("Use second algorithm (enhanced security)")
        self.use_second_algo.stateChanged.connect(self.toggle_second_algorithm)
        
        # Second algorithm selection (initially hidden)
        self.second_algo_form = QFormLayout()
        self.second_encryption_algo = QComboBox()
        self.second_encryption_algo.addItems(["DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"])
        self.second_encryption_algo.setCurrentIndex(1)  # Default to 3DES
        self.second_encryption_algo.currentIndexChanged.connect(self.update_second_algorithm_info)
        self.second_algo_form.addRow("Second Algorithm:", self.second_encryption_algo)
        
        # Second algorithm info
        self.second_algorithm_info = QLabel(get_algorithm_info("3DES"))
        self.second_algorithm_info.setStyleSheet("color: #7f849c; font-style: italic;")
        self.second_algorithm_info.setWordWrap(True)
        self.second_algo_form.addRow(self.second_algorithm_info)
        
        # Second key input
        self.second_encryption_key = QLineEdit()
        self.second_encryption_key.setPlaceholderText("Enter second encryption key")
        self.second_algo_form.addRow("Second Key:", self.second_encryption_key)
        
        # Create a widget for second algorithm
        self.second_algo_widget = QWidget()
        self.second_algo_widget.setLayout(self.second_algo_form)
        self.second_algo_widget.setVisible(False)
        
        # Add to main algorithm layout
        algo_layout.addLayout(algo_form)
        algo_layout.addWidget(self.use_second_algo)
        algo_layout.addWidget(self.second_algo_widget)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # Text to encrypt
        text_group = QGroupBox("Text to Encrypt")
        text_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        text_layout = QVBoxLayout()
        self.text_to_encrypt = QTextEdit()
        text_layout.addWidget(self.text_to_encrypt)
        
        # Encrypt button
        encrypt_btn = QPushButton("Encrypt")
        encrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #7b68ee;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        encrypt_btn.clicked.connect(self.encrypt_text)
        text_layout.addWidget(encrypt_btn)
        
        text_group.setLayout(text_layout)
        layout.addWidget(text_group)
        
        # Encrypted result
        result_group = QGroupBox("Encrypted Text")
        result_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        result_layout = QVBoxLayout()
        self.encrypted_text = QTextEdit()
        self.encrypted_text.setReadOnly(True)
        result_layout.addWidget(self.encrypted_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
    
    def update_algorithm_info(self):
        selected_algo = self.encryption_algo.currentText()
        self.algorithm_info.setText(get_algorithm_info(selected_algo))
    
    def update_second_algorithm_info(self):
        selected_algo = self.second_encryption_algo.currentText()
        self.second_algorithm_info.setText(get_algorithm_info(selected_algo))
    
    def toggle_second_algorithm(self):
        self.second_algo_widget.setVisible(self.use_second_algo.isChecked())
    
    def encrypt_text(self):
        text = self.text_to_encrypt.toPlainText()
        algo1 = self.encryption_algo.currentText()
        key1 = self.encryption_key.text()
        
        if not key1:
            self.encrypted_text.setText("Please enter an encryption key")
            return
            
        if not text:
            self.encrypted_text.setText("Please enter text to encrypt")
            return
        
        # First layer of encryption
        encrypted = encrypt_data(text, algo1, key1)
        
        # Check if second algorithm is enabled
        if self.use_second_algo.isChecked():
            algo2 = self.second_encryption_algo.currentText()
            key2 = self.second_encryption_key.text()
            
            if not key2:
                self.encrypted_text.setText("Please enter a second encryption key")
                return
                
            # Apply second layer of encryption
            encrypted = encrypt_data(encrypted, algo2, key2)
        
        # Convert to base64 for display
        if isinstance(encrypted, bytes):
            result = base64.b64encode(encrypted).decode('utf-8')
        else:
            result = str(encrypted)
            
        self.encrypted_text.setText(result)
    
    # ===================== DECRYPTION TAB ======================
    def setup_decryption_tab(self):
        self.decryption_tab = QWidget()
        layout = QVBoxLayout(self.decryption_tab)
        
        # Text to decrypt
        text_group = QGroupBox("Text to Decrypt")
        text_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        text_layout = QVBoxLayout()
        self.text_to_decrypt = QTextEdit()
        text_layout.addWidget(self.text_to_decrypt)
        
        text_group.setLayout(text_layout)
        layout.addWidget(text_group)
        
        # Decryption controls
        controls_group = QGroupBox("Decryption Settings")
        controls_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        controls_layout = QVBoxLayout()
        
        # Key and algorithm in a horizontal layout
        key_algo_layout = QHBoxLayout()
        
        # Key section
        key_layout = QFormLayout()
        self.decryption_key = QLineEdit()
        self.decryption_key.setPlaceholderText("Enter decryption key")
        key_layout.addRow("Decryption Key:", self.decryption_key)
        
        # Algorithm selection
        algo_layout = QFormLayout()
        self.decryption_algo = QComboBox()
        self.decryption_algo.addItems(["DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"])
        algo_layout.addRow("Algorithm:", self.decryption_algo)
        
        # Add to horizontal layout
        key_algo_layout.addLayout(key_layout)
        key_algo_layout.addLayout(algo_layout)
        
        controls_layout.addLayout(key_algo_layout)
        
        # Action buttons in a horizontal layout
        buttons_layout = QHBoxLayout()
        
        # Detect algorithm button
        detect_btn = QPushButton("Detect Algorithm")
        detect_btn.setStyleSheet("""
            QPushButton {
                background-color: #7b68ee;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        detect_btn.clicked.connect(self.detect_algorithm)
        
        # Decrypt button
        decrypt_btn = QPushButton("Decrypt")
        decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #7b68ee;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        decrypt_btn.clicked.connect(self.decrypt_text)
        
        buttons_layout.addWidget(detect_btn)
        buttons_layout.addWidget(decrypt_btn)
        
        controls_layout.addLayout(buttons_layout)
        
        # Detected algorithm label
        self.detected_algo = QLabel("Detected Algorithm: Unknown")
        self.detected_algo.setStyleSheet("color: #7f849c; font-style: italic;")
        controls_layout.addWidget(self.detected_algo)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Decrypted result
        result_group = QGroupBox("Decrypted Text")
        result_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        result_layout = QVBoxLayout()
        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        result_layout.addWidget(self.decrypted_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
    
    def detect_algorithm(self):
        encrypted_text = self.text_to_decrypt.toPlainText()
        
        if not encrypted_text:
            self.detected_algo.setText("Error: Please enter text to decrypt")
            return
        
        # Detect algorithm
        try:
            detected, confidence = identify_cipher_type(encrypted_text)
            
            # Update the algorithm dropdown
            index = self.decryption_algo.findText(detected)
            if index >= 0:
                self.decryption_algo.setCurrentIndex(index)
            
            # Show confidence scores
            top_algos = sorted(confidence.items(), key=lambda x: x[1], reverse=True)[:3]
            confidence_text = ", ".join([f"{k}: {v}" for k, v in top_algos])
            self.detected_algo.setText(f"Top matches: {confidence_text}")
            
        except Exception as e:
            self.detected_algo.setText(f"Detection error: {str(e)}")
    
    def decrypt_text(self):
        encrypted_text = self.text_to_decrypt.toPlainText()
        key = self.decryption_key.text()
        selected_algo = self.decryption_algo.currentText()
        
        if not encrypted_text:
            self.decrypted_text.setText("Please enter text to decrypt")
            return
        
        if not key:
            self.decrypted_text.setText("Please provide a decryption key")
            return
        
        try:
            # Special handling for Caesar cipher
            if selected_algo == "Caesar Cipher":
                # Just pass the text directly
                result = decrypt_caesar(encrypted_text, key)
            else:
                # For other algorithms, try to decode base64
                try:
                    data = base64.b64decode(encrypted_text)
                except:
                    # If base64 decoding fails, use as is
                    data = encrypted_text.encode('utf-8')
                
                # Decrypt with selected algorithm
                result = decrypt_data(data, selected_algo, key)
            
            self.decrypted_text.setText(str(result))
                
        except Exception as e:
            self.decrypted_text.setText(f"Could not decrypt. Error: {str(e)}")
    
    # ===================== PASSWORD GENERATOR TAB ======================
    def setup_password_generator_tab(self):
        self.password_generator_tab = QWidget()
        layout = QVBoxLayout(self.password_generator_tab)
        
        # Generator settings
        settings_group = QGroupBox("Password Generator")
        settings_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        settings_layout = QVBoxLayout()
        
        # Password length
        length_layout = QFormLayout()
        self.password_length = QSlider(Qt.Horizontal)
        self.password_length.setMinimum(4)
        self.password_length.setMaximum(64)
        self.password_length.setValue(12)
        self.password_length.setTickPosition(QSlider.TicksBelow)
        self.password_length.setTickInterval(4)
        
        self.length_value = QLabel("12")
        self.password_length.valueChanged.connect(lambda v: self.length_value.setText(str(v)))
        
        length_widget = QWidget()
        length_h_layout = QHBoxLayout(length_widget)
        length_h_layout.addWidget(self.password_length)
        length_h_layout.addWidget(self.length_value)
        
        length_layout.addRow("Password Length:", length_widget)
        
        # Password complexity
        complexity_layout = QFormLayout()
        self.password_complexity = QSlider(Qt.Horizontal)
        self.password_complexity.setMinimum(1)
        self.password_complexity.setMaximum(3)
        self.password_complexity.setValue(2)
        self.password_complexity.setTickPosition(QSlider.TicksBelow)
        self.password_complexity.setTickInterval(1)
        
        complexity_layout.addRow("Password Complexity:", self.password_complexity)
        
        # Complexity levels
        levels_layout = QVBoxLayout()
        levels_layout.addWidget(QLabel("Complexity Levels:"))
        level1 = QLabel("1: Letters only")
        level1.setStyleSheet("color: #f38ba8;")
        levels_layout.addWidget(level1)
        
        level2 = QLabel("2: Letters and numbers")
        level2.setStyleSheet("color: #a6e3a1;")
        levels_layout.addWidget(level2)
        
        level3 = QLabel("3: Letters, numbers, and special characters")
        level3.setStyleSheet("color: #89b4fa;")
        levels_layout.addWidget(level3)
        
        # Generate button
        generate_btn = QPushButton("Generate Password")
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #7b68ee;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        generate_btn.clicked.connect(self.generate_password_clicked)
        
        # Generated password display
        result_layout = QHBoxLayout()
        result_layout.addWidget(QLabel("Generated Password:"))
        
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        result_layout.addWidget(self.generated_password)
        
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self.copy_generated_password)
        result_layout.addWidget(copy_btn)
        
        # Add everything to settings layout
        settings_layout.addLayout(length_layout)
        settings_layout.addLayout(complexity_layout)
        settings_layout.addLayout(levels_layout)
        settings_layout.addSpacerItem(QSpacerItem(20, 20))
        settings_layout.addWidget(generate_btn)
        settings_layout.addSpacerItem(QSpacerItem(20, 20))
        settings_layout.addLayout(result_layout)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Admin settings
        admin_group = QGroupBox("Admin Settings")
        admin_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #45475a;
                border-radius: 5px;
                margin-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #7b68ee;
            }
        """)
        
        admin_layout = QVBoxLayout()
        
        admin_form = QFormLayout()
        
        # Username input
        self.new_admin_username = QLineEdit()
        self.new_admin_username.setPlaceholderText("Enter new username")
        admin_form.addRow("New Username:", self.new_admin_username)
        
        # Password input
        self.new_admin_password = QLineEdit()
        self.new_admin_password.setEchoMode(QLineEdit.Password)
        self.new_admin_password.setPlaceholderText("Enter new password")
        admin_form.addRow("New Password:", self.new_admin_password)
        
        # Confirm password
        self.confirm_admin_password = QLineEdit()
        self.confirm_admin_password.setEchoMode(QLineEdit.Password)
        self.confirm_admin_password.setPlaceholderText("Confirm new password")
        admin_form.addRow("Confirm Password:", self.confirm_admin_password)
        
        # Change button
        change_btn = QPushButton("Change Admin Credentials")
        change_btn.setStyleSheet("""
            QPushButton {
                background-color: #7b68ee;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #9370db;
            }
        """)
        change_btn.clicked.connect(self.change_admin_credentials)
        
        # Status message
        self.admin_status = QLabel("")
        self.admin_status.setAlignment(Qt.AlignCenter)
        self.admin_status.setStyleSheet("color: #a6e3a1;")
        
        # Add to layout
        admin_layout.addLayout(admin_form)
        admin_layout.addSpacerItem(QSpacerItem(20, 10))
        admin_layout.addWidget(change_btn)
        admin_layout.addWidget(self.admin_status)
        
        admin_group.setLayout(admin_layout)
        layout.addWidget(admin_group)
        
        # Add a spacer at the end
        layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
    
    def generate_password_clicked(self):
        length = self.password_length.value()
        complexity = self.password_complexity.value()
        
        password = generate_password(length, complexity)
        self.generated_password.setText(password)
    
    def copy_generated_password(self):
        password = self.generated_password.text()
        if password:
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            
            # Show a temporary message box
            QMessageBox.information(self, "Password Copied", "Password has been copied to clipboard!")
    
    def change_admin_credentials(self):
        new_username = self.new_admin_username.text()
        new_password = self.new_admin_password.text()
        confirm_password = self.confirm_admin_password.text()
        
        if not new_username or not new_password:
            self.admin_status.setText("Username and password cannot be empty")
            self.admin_status.setStyleSheet("color: #f38ba8;")
            return
            
        if new_password != confirm_password:
            self.admin_status.setText("Passwords do not match")
            self.admin_status.setStyleSheet("color: #f38ba8;")
            return
        
        global admin_username, admin_password
        admin_username = new_username
        # Store the hashed password
        admin_password = hash_password(new_password)
        
        # Save the new credentials
        if save_credentials(admin_username, new_password):
            self.admin_status.setText("Admin credentials updated successfully")
            self.admin_status.setStyleSheet("color: #a6e3a1;")
            
            # Clear the input fields
            self.new_admin_username.clear()
            self.new_admin_password.clear()
            self.confirm_admin_password.clear()
        else:
            self.admin_status.setText("Error saving credentials")
            self.admin_status.setStyleSheet("color: #f38ba8;")

# Main application
def main():
    # Create application
    app = QApplication(sys.argv)
    
    # Apply custom dark theme directly with stylesheet instead of using qdarktheme
    app.setStyleSheet("""
        QWidget {
            background-color: #1e1e2e;
            color: #cdd6f4;
        }
        QPushButton {
            background-color: #7b68ee;
            color: white;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
            border: none;
        }
        QPushButton:hover {
            background-color: #9370db;
        }
        QLineEdit, QTextEdit, QComboBox {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            border-radius: 4px;
            padding: 4px;
        }
        QTabWidget::pane {
            border: none;
            background-color: #1e1e2e;
        }
        QTabBar::tab {
            background-color: #1e1e2e;
            color: #cdd6f4;
            padding: 8px 20px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #7b68ee;
            color: white;
        }
        QGroupBox {
            border: 1px solid #45475a;
            border-radius: 5px;
            margin-top: 10px;
            font-weight: bold;
            background-color: #1e1e2e;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
            color: #7b68ee;
        }
        QTableWidget {
            background-color: #1e1e2e;
            alternate-background-color: #313244;
            border: 1px solid #45475a;
            gridline-color: #45475a;
            color: #cdd6f4;
            selection-background-color: #7b68ee;
            selection-color: white;
        }
        QTableWidget::item {
            padding: 5px;
            border-bottom: 1px solid #45475a;
        }
        QHeaderView::section {
            background-color: #313244;
            color: #cdd6f4;
            padding: 5px;
            border: 1px solid #45475a;
            font-weight: bold;
        }
        QTableCornerButton::section {
            background-color: #313244;
            border: 1px solid #45475a;
        }
    """)
    
    # Show login dialog
    login_dialog = LoginDialog()
    if login_dialog.exec_():
        # If login successful, show main window
        if login_dialog.get_success():
            window = SecurePasswordToolkitApp()
            window.show()
            sys.exit(app.exec_())

if __name__ == "__main__":
    main()