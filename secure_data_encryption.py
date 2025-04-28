import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib

SALT = b'osama_secure_salt_255'  
ITERATIONS = 100_000

def make_key(password):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'), 
        SALT,
        ITERATIONS
    )
    return base64.urlsafe_b64encode(key)

st.set_page_config(
    page_title="Osama's Secure Vault",
    page_icon="🔒",
    layout="centered"
)

st.title("🛡️ Osama's Secure Vault")
st.caption("Local Encryption Only — Your Information Never Leaves This Machine")

pwd = st.text_input(
    "Your Master Key :", 
    value="osama",  # Default for testing
    type="password"
)

if not pwd:
    st.warning("⚠️ Please Set a Master Key")
    st.stop()

enc_tab, dec_tab = st.tabs(["🔐 Encrypt Message", "🔓 Decrypt Message"])

with enc_tab:
    msg = st.text_area("Message to Encrypt:", "Hello")  # Default message
    if st.button("Encrypt Now"):
        try:
            cipher = Fernet(make_key(pwd))
            encrypted = cipher.encrypt(msg.encode('utf-8'))
            st.code(encrypted.decode('utf-8'), language="text")
        except Exception as e:
            st.error(f"Error: {str(e)}")

with dec_tab:
    enc_msg = st.text_area("Paste Encrypted Message :")
    if st.button("Decrypt Now"):
        try:
            cipher = Fernet(make_key(pwd))
            decrypted = cipher.decrypt(enc_msg.encode('utf-8'))
            st.success(decrypted.decode('utf-8'))
        except:
            st.error("❌ Wrong Key or Invalid Message!")

st.divider()
st.caption("Created by Osama © 2025")
