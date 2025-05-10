import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

stored_data = []  # List of dicts: [{"encrypted_text": ..., "passkey": ...}]
failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data.append({"encrypted_text": encrypted_text, "passkey": hashed_passkey})
            st.success("✅ Data stored securely!")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if passkey:
            hashed_passkey = hash_passkey(passkey)
            match_found = False

            for record in stored_data:
                if record["passkey"] == hashed_passkey:
                    decrypted_text = decrypt_data(record["encrypted_text"])
                    st.success(f"✅ Decrypted Data: {decrypted_text}")
                    match_found = True
                    failed_attempts = 0
                    break

            if not match_found:
                failed_attempts += 1
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state["redirect"] = "Login"
                    st.experimental_rerun()
        else:
            st.error("⚠️ Passkey is required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state["redirect"] = "Retrieve Data"
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

if "redirect" in st.session_state:
    redirect_page = st.session_state.pop("redirect")
    if redirect_page:
        st.experimental_set_query_params(page=redirect_page)
        st.experimental_rerun()
