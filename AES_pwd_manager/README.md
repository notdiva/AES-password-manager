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

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- pip

### Install dependencies

```bash
pip install streamlit pycryptodome
