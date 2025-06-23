# 🔐 AES Password Manager

A secure, offline password manager built with **Streamlit** and **AES encryption** using Python's `pycryptodome`. It allows you to store, retrieve, and manage your passwords safely with a master password system.

---

## 🚀 Features

- 🔑 Set and verify a master password (stored securely as a SHA-256 hash)
- 🔒 AES-256 encryption (CBC mode) for each password
- 🧠 Password strength checker with feedback
- 🔁 Password generator for strong, random passwords
- 📁 Encrypted vault stored locally as JSON
- 💻 Streamlit-based GUI

---

## 🖥️ Live Demo

> You can run the app locally or deploy it on [Streamlit Cloud](https://share.streamlit.io).

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

## ▶️ Running the App
```bash
streamlit run app.py
```

## 📁 File Structure
```bash
├── app.py                # Main Streamlit app
├── requirements.txt      # Python dependencies
├── password_vault.json   # Encrypted password vault (auto-generated)
├── master_key.json       # Master password hash file (auto-generated)
```
## 🛡️ Security Notes
The master password is stored as a hashed string (SHA-256), not in plain text.

Passwords are encrypted using AES-256 in CBC mode with a random IV.

This app is designed for offline personal use. For cloud storage or multi-user support, consider integrating with Firebase or AWS.
