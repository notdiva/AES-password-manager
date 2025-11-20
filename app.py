import streamlit as st
import os
import json
import base64
import hashlib
import string
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --------------------------
# Constants
# --------------------------
VAULT_FILE = "password_vault.json"
MASTER_KEY_FILE = "master_key.json"

# --------------------------
# Helper Functions
# --------------------------
def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    return data[:-ord(data[-1])]

def generate_key(master_password):
    """Generate a 256-bit key from the master password."""
    return hashlib.sha256(master_password.encode()).digest()

def encrypt(data, key):
    """Encrypt data using AES CBC mode."""
    data = pad(data)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt(data, key):
    """Decrypt data using AES CBC mode."""
    try:
        data = base64.b64decode(data)
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted).decode('utf-8')
        return unpad(decrypted)
    except Exception:
        return None

# --------------------------
# Master Password Functions
# --------------------------
def set_master_password(new_password):
    """Set or reset the master password and store it securely."""
    key_hash = hashlib.sha256(new_password.encode()).hexdigest()
    with open(MASTER_KEY_FILE, "w") as file:
        json.dump({"master_key": key_hash}, file)

def verify_master_password(master_password):
    if not os.path.exists("data.json") or os.path.getsize("data.json") == 0:
        return False  # No data to verify

    with open("data.json", "r") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            return False

# --------------------------
# Password Generation & Strength Checker
# --------------------------
def generate_strong_password(length=16):
    """Generate a strong password with letters, digits, and special characters."""
    if length < 8:
        length = 8
    
    all_chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(all_chars, k=length))

def check_password_strength(password):
    """Check the strength of a given password and give feedback."""
    length = len(password)
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    score = sum([has_lower, has_upper, has_digit, has_special])
    feedback = []

    if length < 8:
        feedback.append("Make the password longer (at least 8 characters).")
    if not has_lower:
        feedback.append("Add lowercase letters.")
    if not has_upper:
        feedback.append("Add uppercase letters.")
    if not has_digit:
        feedback.append("Include digits.")
    if not has_special:
        feedback.append("Use special characters (!@#$%^&*).")

    if length >= 12 and score == 4:
        return "Strong 💪", "Your password meets all security criteria!"
    elif length >= 8 and score >= 3:
        return "Moderate 🙂", "Consider adding more special characters or increasing the length."
    else:
        return "Weak ⚠️", " ".join(feedback)

# --------------------------
# Vault Operations
# --------------------------
def load_vault():
    """Load encrypted passwords from the vault."""
    if not os.path.exists(VAULT_FILE):
        return {}
    
    with open(VAULT_FILE, 'r') as file:
        encrypted_data = file.read().strip()

    return json.loads(encrypted_data) if encrypted_data else {}

def save_vault(vault):
    """Save passwords to the vault."""
    with open(VAULT_FILE, 'w') as file:
        file.write(json.dumps(vault))

# --------------------------
# Streamlit UI
# --------------------------

st.title("🔒 AES Password Manager")

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "master_password" not in st.session_state:
    st.session_state.master_password = None

# --------------------------
# Master Password Setup
# --------------------------
if not os.path.exists(MASTER_KEY_FILE):
    st.subheader("🔑 Set Master Password")
    new_master_password = st.text_input("Enter a new Master Password:", type="password")
    confirm_password = st.text_input("Confirm Master Password:", type="password")

    if st.button("Set Master Password"):
        if new_master_password and new_master_password == confirm_password:
            set_master_password(new_master_password)
            st.success("Master Password set successfully! Restart the app to continue.")
        else:
            st.error("Passwords do not match!")

# --------------------------
# Login Screen
# --------------------------
elif not st.session_state.authenticated:
    st.subheader("🔐 Enter Master Password")
    master_password = st.text_input("Master Password:", type="password")

    if st.button("Login"):
        if verify_master_password(master_password):
            st.session_state.authenticated = True
            st.session_state.master_password = master_password
            st.success("Access granted!")
            st.rerun()  # Refresh UI
        else:
            st.error("Incorrect Master Password!")

# --------------------------
# Main Vault Operations (Only if Authenticated)
# --------------------------
if st.session_state.authenticated:
    key = generate_key(st.session_state.master_password)
    vault = load_vault()

    action = st.selectbox("Choose Action", ["Add Password", "Retrieve Password", "Show Vault", "Generate Strong Password", "Reset Master Password"])

    if action == "Add Password":
        service = st.text_input("Enter service name:")
        username = st.text_input("Enter username:")
        generate = st.checkbox("Generate a strong password?")
        
        if generate:
            length = st.number_input("Password Length (min 8, default 16)", min_value=8, value=16)
            password = generate_strong_password(length)
        else:
            password = st.text_input("Enter password:", type="password")
            if password:
                strength, feedback = check_password_strength(password)
                st.write(f"Password Strength: {strength}")
                st.write(feedback)
        
        if st.button("Save Password") and service and username and password:
            encrypted_password = encrypt(password, key)
            vault[service] = {'username': username, 'password': encrypted_password}
            save_vault(vault)
            st.success(f"Password saved for {service}!")

    elif action == "Retrieve Password":
        service = st.text_input("Enter service name:")
        if st.button("Retrieve") and service in vault:
            encrypted_password = vault[service]['password']
            password = decrypt(encrypted_password, key)
            if password:
                st.success(f"Service: {service}\nUsername: {vault[service]['username']}\nPassword: {password}")
            else:
                st.error("Failed to decrypt the password.")
        elif service and service not in vault:
            st.warning("Service not found!")

    elif action == "Show Vault":
        if vault:
            for service, details in vault.items():
                st.write(f"**Service:** {service}\n**Username:** {details['username']}\n**Encrypted Password:** {details['password']}\n---")
        else:
            st.info("No saved passwords.")

    elif action == "Reset Master Password":
        os.remove(MASTER_KEY_FILE)
        st.warning("Master Password reset! Restart the app to set a new one.")

