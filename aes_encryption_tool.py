# AES-256 Encryption Web App using Streamlit
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os

# Constants
KEY_LEN = 32
SALT_LEN = 16
IV_LEN = 16
ITERATIONS = 100000

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=ITERATIONS)

def encrypt(data, password):
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CFB)
    encrypted = cipher.encrypt(data)
    return salt + cipher.iv + encrypted

def decrypt(enc_data, password):
    salt = enc_data[:SALT_LEN]
    iv = enc_data[SALT_LEN:SALT_LEN + IV_LEN]
    ciphertext = enc_data[SALT_LEN + IV_LEN:]
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)

# Streamlit UI
st.set_page_config(page_title="🔐 AES-256 File Encryption Tool")
st.title("🔐 AES-256 File Encryption Tool")

option = st.radio("Choose an operation:", ["Encrypt", "Decrypt"])
password = st.text_input("Enter a password:", type="password")
uploaded_file = st.file_uploader("Upload a file:")

if uploaded_file and password:
    file_bytes = uploaded_file.read()

    if option == "Encrypt":
        encrypted_bytes = encrypt(file_bytes, password)
        st.success("✅ File encrypted successfully!")
        st.download_button("Download Encrypted File", data=encrypted_bytes, file_name=uploaded_file.name + ".enc")

    elif option == "Decrypt":
        try:
            decrypted_bytes = decrypt(file_bytes, password)
            st.success("✅ File decrypted successfully!")
            st.download_button("Download Decrypted File", data=decrypted_bytes, file_name="decrypted_" + uploaded_file.name)
        except Exception as e:
            st.error(f"❌ Decryption failed: {str(e)}")

st.markdown("---")
st.markdown("**Developed using AES-256 with secure key derivation and CFB mode**")
