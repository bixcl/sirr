import dearpygui.dearpygui as dpg
import hashlib
import random
import string
import json
import os
import base64
import math
from Crypto.Cipher import DES, DES3, ARC4, Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# File to store credentials and passwords
CREDENTIALS_FILE = "credentials.json"
PASSWORD_STORE_FILE = "password_store.json"

# Global variables for login
admin_username = "admin"
admin_password = "admin"

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

# Hash password using SHA-256
def hash_password(password):
    if isinstance(password, str):
        password = password.encode('utf-8')
    return hashlib.sha256(password).hexdigest()

# Save credentials to file with password hashing
def save_credentials(username, password):
    try:
        # Get the absolute path to the credentials file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        credentials_path = os.path.join(script_dir, CREDENTIALS_FILE)
        
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
    # Use DES with a fixed key for simplicity
    key = b"SecurityKey123"[:8]  # DES requires 8 bytes key
    return base64.b64encode(encrypt_des(password, key)).decode('utf-8')

def decrypt_password(encrypted):
    key = b"SecurityKey123"[:8]
    try:
        encrypted_bytes = base64.b64decode(encrypted)
        return decrypt_des(encrypted_bytes, key)
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
    # For Caesar cipher, we need to handle it differently than block ciphers
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

def decrypt_substitution(data, key):
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

def encrypt_md5(data, key=None):
    # MD5 is a hash, not encryption, but included for completeness
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest().encode('utf-8')

def decrypt_md5(data, key=None):
    # Cannot decrypt MD5 hash
    return "MD5 is a one-way hash function and cannot be decrypted"

def encrypt_sha1(data, key=None):
    # SHA1 is a hash, not encryption, but included for completeness
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha1(data).hexdigest().encode('utf-8')

def decrypt_sha1(data, key=None):
    # Cannot decrypt SHA-1 hash
    return "SHA-1 is a one-way hash function and cannot be decrypted"

def encrypt_wep(data, key):
    # Simplified WEP implementation
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = ARC4.new(key)  # WEP uses RC4 internally
    if isinstance(data, str):
        data = data.encode('utf-8')
    return cipher.encrypt(data)

def decrypt_wep(data, key, raw=False):
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = ARC4.new(key)  # WEP uses RC4 internally
    result = cipher.decrypt(data)
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

# Function to detect algorithm from encrypted data
def detect_algorithm(data, key=None):
    # This is a simplified detection algorithm that relies on trying each method
    algorithms = ["DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"]
    
    if key:
        for algo in algorithms:
            try:
                result = decrypt_data(data, algo, key)
                # If result looks like text (contains letters and spaces), it might be the right algorithm
                if isinstance(result, str) and any(c.isalpha() for c in result) and ' ' in result:
                    return algo, result
            except:
                continue
    
    return "Unknown", "Could not automatically detect the algorithm"

# Secure password generator
def generate_password(length, complexity):
    chars = string.ascii_letters
    if complexity > 1:
        chars += string.digits
    if complexity > 2:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Callback functions for UI interaction
def login_callback():
    username = dpg.get_value("username_input")
    password = dpg.get_value("password_input")
    
    # Hash the entered password and compare with stored hash
    hashed_input = hash_password(password)
    
    if username == admin_username and hashed_input == admin_password:
        dpg.configure_item("login_window", show=False)
        dpg.configure_item("main_window", show=True)
        refresh_password_list()
    else:
        dpg.set_value("login_status", "Invalid username or password!")

def toggle_second_algorithm():
    show_second = dpg.get_value("use_second_algo")
    dpg.configure_item("second_encryption_algo", show=show_second)
    dpg.configure_item("second_encryption_key", show=show_second)

def encrypt_callback():
    text = dpg.get_value("text_to_encrypt")
    algo1 = dpg.get_value("encryption_algo")
    key1 = dpg.get_value("encryption_key")
    
    if not key1:
        dpg.set_value("encrypted_text", "Please enter an encryption key")
        return
        
    if not text:
        dpg.set_value("encrypted_text", "Please enter text to encrypt")
        return
    
    # First layer of encryption
    encrypted = encrypt_data(text, algo1, key1)
    
    # Check if second algorithm is enabled
    if dpg.get_value("use_second_algo"):
        algo2 = dpg.get_value("second_encryption_algo_combo")
        key2 = dpg.get_value("second_encryption_key_input")
        
        if not key2:
            dpg.set_value("encrypted_text", "Please enter a second encryption key")
            return
            
        # Apply second layer of encryption
        encrypted = encrypt_data(encrypted, algo2, key2)
    
    # Convert to base64 for display
    if isinstance(encrypted, bytes):
        result = base64.b64encode(encrypted).decode('utf-8')
    else:
        result = str(encrypted)
        
    dpg.set_value("encrypted_text", result)

# Add a function to update the UI when detecting algorithms before decryption
def detect_algorithm_callback():
    encrypted_text = dpg.get_value("text_to_decrypt")
    
    if not encrypted_text:
        dpg.set_value("detected_algo", "Error: Please enter text to decrypt")
        return
    
    # First identify the cipher type without key
    try:
        detected_algo, confidence = identify_cipher_type(encrypted_text)
        
        # Update the algorithm dropdown with the detected algorithm
        dpg.set_value("decryption_algo_combo", detected_algo)
        
        # Show confidence scores for top algorithms
        top_algos = sorted(confidence.items(), key=lambda x: x[1], reverse=True)[:3]
        confidence_text = ", ".join([f"{k}: {v}" for k, v in top_algos])
        dpg.set_value("detected_algo", f"Top matches: {confidence_text}")
        
    except Exception as e:
        dpg.set_value("detected_algo", f"Detection error: {str(e)}")

# Update decrypt callback to use the selected algorithm
def decrypt_callback():
    encrypted_text = dpg.get_value("text_to_decrypt")
    key = dpg.get_value("decryption_key")
    selected_algo = dpg.get_value("decryption_algo_combo")
    
    if not encrypted_text:
        dpg.set_value("decrypted_text", "Please enter text to decrypt")
        return
    
    if not key:
        dpg.set_value("decrypted_text", "Please provide a decryption key")
        return
    
    try:
        # Special handling for Caesar cipher - don't try to base64 decode if it's Caesar
        if selected_algo == "Caesar Cipher":
            # For Caesar cipher, just pass the text directly without trying to decode it
            result = decrypt_caesar(encrypted_text, key)
        else:
            # For other algorithms, try to decode base64 first
            try:
                data = base64.b64decode(encrypted_text)
            except:
                # If base64 decoding fails, use as is
                data = encrypted_text.encode('utf-8')
            
            # Use the manually selected algorithm
            result = decrypt_data(data, selected_algo, key)
            
        dpg.set_value("decrypted_text", result)
            
    except Exception as e:
        dpg.set_value("decrypted_text", f"Could not decrypt. Error: {str(e)}")

def generate_password_callback():
    length = dpg.get_value("password_length")
    complexity = dpg.get_value("password_complexity")
    generated = generate_password(length, complexity)
    dpg.set_value("generated_password", generated)

def save_password_callback():
    site = dpg.get_value("pm_site")
    username = dpg.get_value("pm_username")
    password = dpg.get_value("pm_password")
    
    if not site or not username or not password:
        dpg.set_value("pm_status", "Please fill in all fields")
        return
    
    if save_password(site, username, password):
        dpg.set_value("pm_status", f"Password saved for {site}")
        # Clear the input fields
        dpg.set_value("pm_site", "")
        dpg.set_value("pm_username", "")
        dpg.set_value("pm_password", "")
        # Refresh the password list
        refresh_password_list()
    else:
        dpg.set_value("pm_status", "Error saving password")

def refresh_password_list():
    # Clear the existing list
    if dpg.does_item_exist("password_list"):
        dpg.delete_item("password_list")
    
    passwords = load_passwords()
    with dpg.table(tag="password_list", parent="password_container", header_row=True, policy=dpg.mvTable_SizingFixedFit, borders_innerH=True, borders_outerH=True, borders_innerV=True, borders_outerV=True):
        # Add the columns
        dpg.add_table_column(label="Site")
        dpg.add_table_column(label="Username")
        dpg.add_table_column(label="Password")
        dpg.add_table_column(label="Actions")
        
        # Add the rows
        row_id = 0
        for site, entries in passwords.items():
            for i, entry in enumerate(entries):
                with dpg.table_row():
                    dpg.add_text(site)
                    
                    # Add masked username
                    username_tag = f"username_{row_id}"
                    dpg.add_text("********", tag=username_tag)
                    
                    # Add masked password
                    password_tag = f"password_{row_id}"
                    dpg.add_text("********", tag=password_tag)
                    
                    with dpg.group(horizontal=True):
                        # Create buttons that call the appropriate functions
                        show_btn_tag = f"show_btn_{row_id}"
                        copy_btn_tag = f"copy_btn_{row_id}"
                        del_btn_tag = f"del_btn_{row_id}"
                        
                        # Store the encrypted values for this row
                        enc_pwd = entry["password"]
                        enc_user = entry["username"]
                        site_name = site
                        
                        # Use separate functions for each button to avoid the lambda issue
                        def make_show_callback(u_tag, p_tag, p_enc, u_enc):
                            def show_callback():
                                show_password_and_username(u_tag, p_tag, p_enc, u_enc)
                            return show_callback
                        
                        def make_copy_callback(p_enc):
                            def copy_callback():
                                copy_password(p_enc)
                            return copy_callback
                        
                        def make_delete_callback(p_site, u_enc):
                            def delete_callback():
                                delete_password(p_site, u_enc)
                            return delete_callback
                        
                        dpg.add_button(label="Show", tag=show_btn_tag, 
                                       callback=make_show_callback(username_tag, password_tag, enc_pwd, enc_user))
                        dpg.add_button(label="Copy", tag=copy_btn_tag, callback=make_copy_callback(enc_pwd))
                        dpg.add_button(label="Delete", tag=del_btn_tag, callback=make_delete_callback(site_name, enc_user))
                
                row_id += 1

def show_password(tag, encrypted_password):
    decrypted = decrypt_password(encrypted_password)
    is_showing = dpg.get_value(tag) != "********"
    
    if is_showing:
        dpg.set_value(tag, "********")
    else:
        dpg.set_value(tag, decrypted)

def delete_password(site, encrypted_username):
    passwords = load_passwords()
    if site in passwords:
        # Filter out the entry with the matching encrypted username
        passwords[site] = [entry for entry in passwords[site] if entry["username"] != encrypted_username]
        if not passwords[site]:
            del passwords[site]
        
        with open(PASSWORD_STORE_FILE, 'w') as f:
            json.dump(passwords, f)
        
        refresh_password_list()

def change_admin_credentials():
    new_username = dpg.get_value("new_admin_username")
    new_password = dpg.get_value("new_admin_password")
    confirm_password = dpg.get_value("confirm_admin_password")
    
    if not new_username or not new_password:
        dpg.set_value("admin_change_status", "Username and password cannot be empty")
        return
        
    if new_password != confirm_password:
        dpg.set_value("admin_change_status", "Passwords do not match")
        return
    
    global admin_username, admin_password
    admin_username = new_username
    # Store the hashed password
    admin_password = hash_password(new_password)
    
    # Save the new credentials
    save_credentials(admin_username, admin_password)
    
    dpg.set_value("admin_change_status", "Admin credentials updated successfully")
    # Clear the input fields
    dpg.set_value("new_admin_username", "")
    dpg.set_value("new_admin_password", "")
    dpg.set_value("confirm_admin_password", "")

def copy_password(encrypted_password):
    try:
        decrypted = decrypt_password(encrypted_password)
        dpg.set_clipboard_text(decrypted)
        # Show a temporary success message
        if dpg.does_item_exist("copy_success_text"):
            dpg.delete_item("copy_success_text")
        dpg.add_text("Password copied to clipboard!", tag="copy_success_text", parent="password_container")
        # Hide the message after 3 seconds
        dpg.set_value("pm_status", "Password copied to clipboard")
    except Exception as e:
        dpg.set_value("pm_status", f"Error copying password: {str(e)}")

# Add algorithm info for encryption selection
def update_algorithm_info():
    selected_algo = dpg.get_value("encryption_algo")
    algorithm_info = get_algorithm_info(selected_algo)
    dpg.set_value("algorithm_info", algorithm_info)
    
# Add algorithm info for second encryption selection
def update_second_algorithm_info():
    selected_algo = dpg.get_value("second_encryption_algo_combo")
    algorithm_info = get_algorithm_info(selected_algo)
    dpg.set_value("second_algorithm_info", algorithm_info)

# Get information about the selected algorithm
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

# Function to detect algorithm without requiring a key
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
        
        # Check if it's plain text (could be Caesar/Substitution)
        if isinstance(data, str) and not base64_successful:
            try:
                is_text = all(c.isprintable() for c in data)
                if is_text:
                    characteristics["Caesar Cipher"] += 5
                    characteristics["Substitution"] += 3
                    # Binary ciphers are unlikely to produce printable text
                    characteristics["DES"] -= 3
                    characteristics["3DES"] -= 3
                    characteristics["Blowfish"] -= 3
                    characteristics["RC4"] -= 2
            except:
                pass
              
        # Sample the first few bytes for patterns specific to each algorithm
        # DES/3DES/Blowfish all have 8-byte blocks but can be distinguished
        # by examining patterns in their outputs
        
        # Check data length (key distinguisher between algorithms)
        data_len = len(decoded)
        
        # Data length must be a multiple of 8 for block ciphers with 8-byte blocks
        if data_len % 8 == 0:
            # Basic boost for all block ciphers
            characteristics["DES"] += 2
            characteristics["3DES"] += 2
            characteristics["Blowfish"] += 2
            
            # 3DES typically produces outputs with more entropy than DES
            if data_len > 24:  # More than 3 blocks
                characteristics["3DES"] += 3
            elif data_len > 16:  # 2-3 blocks
                characteristics["3DES"] += 2
                characteristics["Blowfish"] += 1
            else:  # 1-2 blocks, common for DES
                characteristics["DES"] += 2
        else:
            # Not a multiple of 8 - less likely to be a block cipher
            characteristics["DES"] -= 2
            characteristics["3DES"] -= 2
            characteristics["Blowfish"] -= 2
            # More likely to be RC4 (stream cipher) or simple cipher
            characteristics["RC4"] += 1
            
        # Calculate byte frequency distribution - key for distinguishing algorithms
        byte_counts = {}
        for b in decoded:
            byte_counts[b] = byte_counts.get(b, 0) + 1
            
        # Calculate entropy - higher values indicate more randomness
        entropy = 0
        for count in byte_counts.values():
            prob = count / len(decoded)
            entropy -= prob * (math.log2(prob) if prob > 0 else 0)
            
        # Examine unique byte count - higher count suggests stronger encryption
        unique_bytes = len(byte_counts)
        unique_ratio = unique_bytes / min(256, data_len)
        
        # Typical entropy patterns for different algorithms:
        # 3DES typically has highest entropy
        if entropy > 7.5:
            characteristics["3DES"] += 5
            characteristics["Blowfish"] += 4
            characteristics["RC4"] += 3
            characteristics["DES"] += 2
            # Simple ciphers typically have lower entropy
            characteristics["Caesar Cipher"] -= 3
            characteristics["Substitution"] -= 2
            
        # DES typically has medium-high entropy
        elif 6.5 < entropy <= 7.5:
            characteristics["DES"] += 5
            characteristics["Blowfish"] += 3
            characteristics["RC4"] += 3
            characteristics["3DES"] += 2
            
        # RC4 can have variable entropy
        elif 5.0 < entropy <= 6.5:
            characteristics["RC4"] += 4
            characteristics["DES"] += 3
            characteristics["Substitution"] += 2
            
        # Low entropy suggests simple ciphers
        else:
            characteristics["Caesar Cipher"] += 4
            characteristics["Substitution"] += 3
            # Reduce scores for complex algorithms with unusually low entropy
            characteristics["3DES"] -= 3
            characteristics["Blowfish"] -= 2
            characteristics["DES"] -= 1
        
        # Check uniqueness of bytes - higher uniqueness suggests stronger encryption
        if unique_ratio > 0.7:  # Highly varied byte distribution
            characteristics["3DES"] += 4
            characteristics["Blowfish"] += 3
            characteristics["RC4"] += 3
            characteristics["DES"] += 2
        
        # Check for ASCII text patterns
        ascii_ratio = sum(32 <= b <= 126 for b in decoded) / data_len if data_len else 0
        
        if ascii_ratio > 0.9:  # Mostly printable ASCII
            characteristics["Caesar Cipher"] += 5
            characteristics["Substitution"] += 4
            # Binary ciphers rarely produce mostly ASCII output
            characteristics["DES"] -= 3
            characteristics["3DES"] -= 4
            characteristics["RC4"] -= 2
            characteristics["Blowfish"] -= 3
        elif ascii_ratio < 0.3:  # Mostly non-printable
            characteristics["DES"] += 2
            characteristics["3DES"] += 3
            characteristics["Blowfish"] += 3
            characteristics["RC4"] += 2
            # Simple ciphers generally preserve text properties
            characteristics["Caesar Cipher"] -= 5
            characteristics["Substitution"] -= 3
        
        # Pattern analysis - check for repeating patterns that might indicate block structure
        if data_len > 16:
            # Look for repeating patterns at block boundaries
            des_pattern = 0
            blowfish_pattern = 0
            threedes_pattern = 0
            
            # Check patterns at block boundaries
            for i in range(8, data_len - 8, 8):
                # Simplified pattern detection - actual implementation would be more sophisticated
                if decoded[i-2:i].count(decoded[i]) > 0:
                    des_pattern += 1
                if decoded[i-3:i].count(decoded[i+1:i+4]) > 0:
                    blowfish_pattern += 1
                if i >= 16 and decoded[i-8:i].count(decoded[i:i+8]) > 0:
                    threedes_pattern += 1
            
            # Apply pattern scores
            characteristics["DES"] += min(des_pattern, 3)  # Cap the score
            characteristics["Blowfish"] += min(blowfish_pattern, 3)
            characteristics["3DES"] += min(threedes_pattern, 3)
        
        # Apply final balancing to ensure proper detection
        # Make sure algorithms are distinguishable
        if characteristics["DES"] > 0 and characteristics["3DES"] > 0:
            if abs(characteristics["DES"] - characteristics["3DES"]) < 2:
                # They're too close, boost the one with higher entropy
                if entropy > 7.0:
                    characteristics["3DES"] += 2
                else:
                    characteristics["DES"] += 2
        
        # Find most likely algorithm
        most_likely = max(characteristics.items(), key=lambda x: x[1])
        return most_likely[0], characteristics
    
    except Exception as e:
        print(f"Error in cipher detection: {e}")
        return "Unknown", {"error": str(e)}

# Create responsive layouts
def create_responsive_layout():
    # No special handlers needed - we'll use a simpler approach
    # Just initially position the windows centrally
    dpg.set_item_pos("login_window", [250, 200])

    # For the login callback, modify it to properly center and resize the main window
    original_login = login_callback
    
    def enhanced_login():
        # Call original login function
        original_login()
        
        # After login succeeds, resize and center the main window
        viewport_width = dpg.get_viewport_width()
        viewport_height = dpg.get_viewport_height()
        
        # Set main window to 90% of viewport size
        new_width = int(viewport_width * 0.9)
        new_height = int(viewport_height * 0.9)
        
        # Calculate center position
        center_x = int((viewport_width - new_width) / 2)
        center_y = int((viewport_height - new_height) / 2)
        
        # Update main window size and position
        dpg.configure_item("main_window", width=new_width, height=new_height)
        dpg.set_item_pos("main_window", [center_x, center_y])
    
    # Replace original login with our enhanced version
    globals()["login_callback"] = enhanced_login

def show_password_and_username(username_tag, password_tag, encrypted_password, encrypted_username):
    # Decrypt both username and password
    decrypted_pwd = decrypt_password(encrypted_password)
    decrypted_user = decrypt_password(encrypted_username)
    
    # Check if currently showing or masked
    is_pwd_showing = dpg.get_value(password_tag) != "********"
    
    # Toggle display for both username and password
    if is_pwd_showing:
        dpg.set_value(username_tag, "********")
        dpg.set_value(password_tag, "********")
    else:
        dpg.set_value(username_tag, decrypted_user)
        dpg.set_value(password_tag, decrypted_pwd)

# Load saved credentials
load_credentials()

# Initialize DearPyGUI
dpg.create_context()

# Create modern theme with simple, clean styling
with dpg.theme() as global_theme:
    with dpg.theme_component(dpg.mvAll):
        # Background colors - dark theme
        dpg.add_theme_color(dpg.mvThemeCol_WindowBg, [20, 22, 35, 255])
        dpg.add_theme_color(dpg.mvThemeCol_ChildBg, [25, 27, 40, 255])
        dpg.add_theme_color(dpg.mvThemeCol_PopupBg, [25, 27, 40, 255])
        dpg.add_theme_color(dpg.mvThemeCol_Border, [40, 45, 60, 255])
        
        # Text colors
        dpg.add_theme_color(dpg.mvThemeCol_Text, [220, 220, 220, 255])
        dpg.add_theme_color(dpg.mvThemeCol_TextDisabled, [128, 128, 128, 255])
        
        # Button colors - blue theme
        dpg.add_theme_color(dpg.mvThemeCol_Button, [36, 62, 99, 255])
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, [46, 77, 120, 255])
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [56, 92, 141, 255])
        
        # Frame colors
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, [30, 33, 45, 255])
        dpg.add_theme_color(dpg.mvThemeCol_FrameBgHovered, [40, 43, 55, 255])
        dpg.add_theme_color(dpg.mvThemeCol_FrameBgActive, [45, 48, 60, 255])
        
        # Tab colors
        dpg.add_theme_color(dpg.mvThemeCol_Tab, [36, 62, 99, 255])
        dpg.add_theme_color(dpg.mvThemeCol_TabHovered, [46, 77, 120, 255])
        dpg.add_theme_color(dpg.mvThemeCol_TabActive, [56, 92, 141, 255])
        
        # Header colors
        dpg.add_theme_color(dpg.mvThemeCol_Header, [36, 62, 99, 255])
        dpg.add_theme_color(dpg.mvThemeCol_HeaderHovered, [46, 77, 120, 255])
        dpg.add_theme_color(dpg.mvThemeCol_HeaderActive, [56, 92, 141, 255])
        
        # Table colors
        dpg.add_theme_color(dpg.mvThemeCol_TableHeaderBg, [36, 62, 99, 255])
        dpg.add_theme_color(dpg.mvThemeCol_TableBorderStrong, [40, 45, 60, 255])
        dpg.add_theme_color(dpg.mvThemeCol_TableBorderLight, [35, 40, 50, 255])
        
        # Style - more moderate rounding and spacing
        dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 4.0)
        dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 4.0)
        dpg.add_theme_style(dpg.mvStyleVar_ChildRounding, 4.0)
        dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 6.0, 4.0)
        dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 6.0, 4.0)
        dpg.add_theme_style(dpg.mvStyleVar_ScrollbarSize, 10.0)
        dpg.add_theme_style(dpg.mvStyleVar_ScrollbarRounding, 4.0)
        dpg.add_theme_style(dpg.mvStyleVar_GrabMinSize, 8.0)
        dpg.add_theme_style(dpg.mvStyleVar_GrabRounding, 3.0)

# Create the login window
with dpg.window(tag="login_window", label="Secure Password Toolkit - Login", width=400, height=300, no_close=True, pos=[250, 200]):
    dpg.add_spacer(height=10)
    dpg.add_text("Secure Password Toolkit", color=[66, 150, 250])
    dpg.add_separator()
    dpg.add_spacer(height=20)
    
    dpg.add_text("Welcome back", color=[180, 200, 255])
    dpg.add_text("Please login to continue", color=[180, 200, 255])
    dpg.add_spacer(height=20)
    
    dpg.add_text("Username:")
    dpg.add_input_text(tag="username_input", width=-1)
    
    dpg.add_spacer(height=10)
    
    dpg.add_text("Password:")
    dpg.add_input_text(tag="password_input", password=True, width=-1)
    
    dpg.add_spacer(height=20)
    
    dpg.add_button(label="Login", width=-1, height=35, callback=login_callback)
    dpg.add_spacer(height=5)
    dpg.add_text("", tag="login_status", color=[255, 100, 100])

# Create the main window (hidden initially)
with dpg.window(tag="main_window", label="Secure Password Toolkit", width=800, height=600, show=False, no_close=True, pos=[50, 50]):
    dpg.add_spacer(height=5)
    dpg.add_text("Secure Password Toolkit", color=[66, 150, 250])
    dpg.add_separator()
    dpg.add_spacer(height=5)
    
    with dpg.tab_bar(tag="main_tabs"):
        # Password Manager Tab
        with dpg.tab(label="Password Manager"):
            dpg.add_spacer(height=10)
            dpg.add_text("Add New Password", color=[100, 180, 255])
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Website/Service
            dpg.add_text("Website/Service:")
            dpg.add_input_text(tag="pm_site", width=300)
            
            dpg.add_spacer(height=5)
            
            # Username
            dpg.add_text("Username:")
            dpg.add_input_text(tag="pm_username", width=300)
            
            dpg.add_spacer(height=5)
            
            # Password
            dpg.add_text("Password:")
            dpg.add_input_text(tag="pm_password", password=True, width=300)
            
            dpg.add_spacer(height=10)
            dpg.add_button(label="Save Password", width=300, callback=save_password_callback)
            dpg.add_text("", tag="pm_status", color=[0, 255, 0])
            
            dpg.add_spacer(height=10)
            
            # Saved passwords section
            dpg.add_text("Saved Passwords", color=[100, 180, 255])
            dpg.add_button(label="Refresh List", callback=refresh_password_list)
            dpg.add_separator()
            dpg.add_child_window(tag="password_container", width=775, height=300)
            
        # Encryption Tab
        with dpg.tab(label="Encryption"):
            dpg.add_spacer(height=10)
            dpg.add_text("Encryption", color=[100, 180, 255])
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Algorithm selection
            dpg.add_text("Encryption Algorithm:")
            dpg.add_combo(
                ("DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"), 
                default_value="DES", 
                tag="encryption_algo",
                width=300,
                callback=update_algorithm_info
            )
            
            dpg.add_text("Block cipher with 8-byte key. Requires key and uses padding.", tag="algorithm_info", color=[180, 180, 180], wrap=700)
            
            dpg.add_spacer(height=5)
            dpg.add_text("Encryption Key:")
            dpg.add_input_text(tag="encryption_key", width=300)
            
            dpg.add_spacer(height=5)
            dpg.add_checkbox(label="Use second algorithm (enhanced security)", tag="use_second_algo", callback=toggle_second_algorithm)
            
            # Second algorithm (hidden by default)
            with dpg.group(show=False, tag="second_encryption_algo"):
                dpg.add_text("Second Algorithm:")
                dpg.add_combo(
                    ("DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"), 
                    default_value="3DES", 
                    width=300,
                    tag="second_encryption_algo_combo",
                    callback=update_second_algorithm_info
                )
                dpg.add_text("Triple DES uses 24-byte key. More secure than DES.", tag="second_algorithm_info", color=[180, 180, 180], wrap=700)
            
            with dpg.group(show=False, tag="second_encryption_key"):
                dpg.add_text("Second Key:")
                dpg.add_input_text(tag="second_encryption_key_input", width=300)
            
            dpg.add_spacer(height=10)
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Text input
            dpg.add_text("Text to Encrypt:")
            dpg.add_input_text(tag="text_to_encrypt", multiline=True, width=775, height=100)
            
            dpg.add_spacer(height=5)
            dpg.add_button(label="Encrypt", width=775, callback=encrypt_callback)
            
            dpg.add_spacer(height=5)
            
            # Results
            dpg.add_text("Encrypted Text:")
            dpg.add_input_text(tag="encrypted_text", multiline=True, width=775, height=100, readonly=True)
            
        # Decryption Tab
        with dpg.tab(label="Decryption"):
            dpg.add_spacer(height=10)
            dpg.add_text("Decryption", color=[100, 180, 255])
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Input text
            dpg.add_text("Text to Decrypt:")
            dpg.add_input_text(tag="text_to_decrypt", multiline=True, width=775, height=100)
            
            dpg.add_spacer(height=10)
            
            # Controls
            with dpg.group(horizontal=True):
                with dpg.group():
                    dpg.add_text("Decryption Key:")
                    dpg.add_input_text(tag="decryption_key", width=350)
                
                dpg.add_spacer(width=30)
                
                with dpg.group():
                    dpg.add_text("Algorithm:")
                    dpg.add_combo(
                        ("DES", "3DES", "RC4", "Caesar Cipher", "Substitution", "Blowfish"), 
                        default_value="DES", 
                        tag="decryption_algo_combo",
                        width=350
                    )
            
            dpg.add_spacer(height=10)
            
            # Action buttons
            with dpg.group(horizontal=True):
                dpg.add_button(label="Detect Algorithm", width=375, callback=detect_algorithm_callback)
                dpg.add_spacer(width=25)
                dpg.add_button(label="Decrypt", width=375, callback=decrypt_callback)
            
            dpg.add_text("Detected Algorithm: Unknown", tag="detected_algo", color=[180, 180, 180])
            
            dpg.add_spacer(height=5)
            dpg.add_separator()
            dpg.add_spacer(height=5)
            
            # Results
            dpg.add_text("Decrypted Text:")
            dpg.add_input_text(tag="decrypted_text", multiline=True, width=775, height=100, readonly=True)
            
        # Password Generator Tab
        with dpg.tab(label="Password Generator"):
            dpg.add_spacer(height=10)
            dpg.add_text("Password Generator", color=[100, 180, 255])
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Generator options
            dpg.add_text("Password Length:")
            dpg.add_slider_int(tag="password_length", default_value=12, min_value=4, max_value=64, width=300)
            
            dpg.add_spacer(height=10)
            
            dpg.add_text("Password Complexity:")
            dpg.add_slider_int(tag="password_complexity", default_value=2, min_value=1, max_value=3, width=300)
            
            dpg.add_spacer(height=10)
            
            # Complexity guide
            dpg.add_text("Complexity Levels:")
            dpg.add_text("1: Letters only", color=[255, 150, 150])
            dpg.add_text("2: Letters and numbers", color=[150, 255, 150])
            dpg.add_text("3: Letters, numbers, and special characters", color=[150, 150, 255])
            
            dpg.add_spacer(height=20)
            dpg.add_button(label="Generate Password", width=300, callback=generate_password_callback)
            
            dpg.add_spacer(height=10)
            
            # Generated password
            with dpg.group(horizontal=True):
                dpg.add_text("Generated Password:")
                dpg.add_input_text(tag="generated_password", width=400, readonly=True)
                dpg.add_button(label="Copy", callback=lambda: dpg.set_clipboard_text(dpg.get_value("generated_password")))
            
            dpg.add_spacer(height=20)
            dpg.add_separator()
            dpg.add_spacer(height=10)
            
            # Admin settings
            dpg.add_text("Admin Settings", color=[100, 180, 255])
            
            dpg.add_text("New Username:")
            dpg.add_input_text(tag="new_admin_username", width=300)
            
            dpg.add_spacer(height=5)
            dpg.add_text("New Password:")
            dpg.add_input_text(tag="new_admin_password", password=True, width=300)
            
            dpg.add_spacer(height=5)
            dpg.add_text("Confirm Password:")
            dpg.add_input_text(tag="confirm_admin_password", password=True, width=300)
            
            dpg.add_spacer(height=10)
            dpg.add_button(label="Change Admin Credentials", width=300, callback=change_admin_credentials)
            dpg.add_text("", tag="admin_change_status", color=[0, 255, 0])

# Create responsive layout
create_responsive_layout()

# Apply theme
dpg.bind_theme(global_theme)

# Configure the viewport
dpg.create_viewport(title="Secure Password Toolkit", width=900, height=700)
dpg.configure_viewport(0, x_pos=0, y_pos=0, width=900, height=700, clear_color=[15, 15, 20, 255])  # Dark background for the entire viewport

dpg.setup_dearpygui()
dpg.show_viewport()

# Set the login window to primary and center it
dpg.set_primary_window("login_window", True)

# Start DearPyGUI
dpg.start_dearpygui()
dpg.destroy_context()