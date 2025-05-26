import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

KEY_FILE = "simple_secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
            
    return key


cipher = Fernet(load_key())

def init_db():
    conn = sqlite3.connect("simple_data.db")
    c = conn.cursor()
    c.execute("""
              CREATE TABLE IF NOT EXISTS vault (
                    label TEXT PRIMARY KEY,
                    encrypted_text TEXT,
                    passkey TEXT
                )
                """)
    
    conn.commit()
    conn.close()
    
init_db()

# to convert the pass key into a hash object. means in a more secured way of 64 characters using the hashlib.
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# encryption of text, means converting the text into a series of characters that cannot be read easily.
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

# converted the encrypted text back to readable format using the correct key
def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()


# Streamlit work

st.title("Secure Data Encryption by Muhammad Shariq")

# Side bar functionality
menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("Choose Option", menu)

if choice == "Store Secret":
    st.header("Store a New Secret!")
    
    label = st.text_input("Lable (Unique ID)")
    secret = st.text_area("Enter Your Secret")
    passkey = st.text_input("Passkey (To Retrieve This Secret)", type="password")
    
    if st.button("Encrypt & Save"):
        if label and secret and passkey:
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            
            encrypted = encrypt(secret)
            hashed_key = hash_passkey(passkey)
            
            try:
                c.execute("INSERT INTO vault (label, encrypted_text, passkey) VALUES (?, ?, ?)", 
                          (label, encrypted, hashed_key))
                
                conn.commit()
                st.success("Secret Saved Successfully!")
                
            except sqlite3.IntegrityError:
                st.error("Label already exists!")
                
            conn.close()
            
        else:
            st.warning("Please fill all fields!")
            
    
elif choice == "Retrieve Secret":
    st.header("Retrieve Your Secret") # Header
    
    label = st.text_input("Enter Label to Retrieve Secret")
    passkey = st.text_input("Enter passkey of the Label", type="password")
    
    if st.button("Decrypt"):
        conn = sqlite3.connect("simple_data.db")
        c = conn.cursor()
        c.execute("SELECT encrypted_text, passkey FROM vault WHERE label=?", (label, ))
        
        result = c.fetchone()
        conn.close()
        
        if result:
            encrypted_text , stored_hash = result
            
            if hash_passkey(passkey) == stored_hash:
                decrypted = decrypt(encrypted_text)
                
                st.success("Here is your Secret!")
                
                st.code(decrypted)
                
            else:
                st.error("Incorrect passkey")
                
        else:
            st.warning("No such Label found!")
        

