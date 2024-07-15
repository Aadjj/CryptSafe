import streamlit as st
import csv
from cryptography.fernet import Fernet
import os
import hashlib
import re

# Constants for file paths
KEY_PATH = 'key.key'
PASSWORDS_CSV = 'passwords.csv'
USERS_CSV = 'users.csv'

# Function to load or generate encryption key
def load_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_PATH, 'wb') as key_file:
            key_file.write(key)
        return key

# Function to encrypt data
def encrypt_data(key, data):
    return Fernet(key).encrypt(data.encode())

# Function to decrypt data
def decrypt_data(key, encrypted_data):
    try:
        return Fernet(key).decrypt(encrypted_data).decode()
    except Exception as e:
        st.error(f"Error decrypting data: {e}")
        return None

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Password strength validation
def validate_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit."
    if not re.search(r"[@$!%*?&]", password):
        return "Password must contain at least one special character (@, $, !, %, *, ?, &)."
    return None

# Function to store password in CSV
def store_password_in_csv(service_name, username, password):
    try:
        key = load_key()
        encrypted_password = encrypt_data(key, password)
        file_exists = os.path.exists(PASSWORDS_CSV)
        with open(PASSWORDS_CSV, mode='a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=['Service Name', 'Username', 'Password'])
            if not file_exists:
                writer.writeheader()
            writer.writerow({'Service Name': service_name, 'Username': username, 'Password': encrypted_password.decode()})
    except Exception as e:
        st.error(f"Error storing password: {e}")

# Function to retrieve password from CSV
def retrieve_password_from_csv(service_name):
    try:
        key = load_key()
        with open(PASSWORDS_CSV, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row['Service Name'] == service_name:
                    username = row['Username']
                    encrypted_password = row['Password'].encode()
                    password = decrypt_data(key, encrypted_password)
                    return username, password
        return None, None
    except Exception as e:
        st.error(f"Error retrieving password: {e}")
        return None, None

# Function to list all stored services
def list_all_services():
    services = []
    try:
        with open(PASSWORDS_CSV, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                services.append(row['Service Name'])
    except Exception as e:
        st.error(f"Error listing services: {e}")
    return services

# Function to delete a stored password
def delete_password(service_name):
    try:
        rows = []
        with open(PASSWORDS_CSV, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row['Service Name'] != service_name:
                    rows.append(row)
        with open(PASSWORDS_CSV, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=['Service Name', 'Username', 'Password'])
            writer.writeheader()
            writer.writerows(rows)
    except Exception as e:
        st.error(f"Error deleting password: {e}")

# Function to verify user credentials
def verify_user(username, password):
    try:
        hashed_password = hash_password(password)
        with open(USERS_CSV, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row['Username'] == username and row['Password'] == hashed_password:
                    return True
        return False
    except Exception as e:
        st.error(f"Error verifying user: {e}")
        return False

# Function to register a new user
def register_user(username, password):
    try:
        hashed_password = hash_password(password)
        file_exists = os.path.exists(USERS_CSV)
        with open(USERS_CSV, mode='a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=['Username', 'Password'])
            if not file_exists:
                writer.writeheader()
            writer.writerow({'Username': username, 'Password': hashed_password})
    except Exception as e:
        st.error(f"Error registering user: {e}")

# Streamlit interface for login and registration
def main():
    st.title("CryptSafe")

    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Select Option", menu)

    # Initialize session state variables if they do not exist
    for key in ['username', 'password', 'store_service_name', 'store_service_username', 'store_service_password', 'retrieve_service_name']:
        if key not in st.session_state:
            st.session_state[key] = ""

    if choice == "Login":
        st.subheader("Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")

        if st.button("Login"):
            if verify_user(login_username, login_password):
                st.session_state.username = login_username
                st.success("Logged in successfully!")
            else:
                st.error("Invalid username or password. Please try again.")

    elif choice == "Register":
        st.subheader("Register")
        register_username = st.text_input("New Username", key="register_username")
        register_password = st.text_input("New Password", type="password", key="register_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm_password")

        if st.button("Register"):
            if register_password == confirm_password:
                validation_error = validate_password_strength(register_password)
                if validation_error:
                    st.warning(validation_error)
                else:
                    register_user(register_username, register_password)
                    st.success("Registration successful! You can now login.")
            else:
                st.warning("Passwords do not match. Please re-enter.")

    if st.session_state.username:
        st.markdown("## Store Password")
        store_service_name = st.text_input("Service Name", key="store_service_name")
        store_service_username = st.text_input("Username", key="store_service_username")
        store_service_password = st.text_input("Password", type="password", key="store_service_password")

        if st.button("Save Password"):
            validation_error = validate_password_strength(store_service_password)
            if validation_error:
                st.warning(validation_error)
            else:
                store_password_in_csv(store_service_name, store_service_username, store_service_password)
                st.success("Password saved successfully!")

        st.markdown("## Retrieve Password")
        retrieve_service_name = st.text_input("Service Name", key="retrieve_service_name")

        if st.button("Retrieve Password"):
            retrieved_username, retrieved_password = retrieve_password_from_csv(retrieve_service_name)
            if retrieved_username and retrieved_password:
                st.success(f"Username: {retrieved_username}")
                st.success(f"Password: {retrieved_password}")
            else:
                st.warning(f"Password for {retrieve_service_name} not found.")

        st.markdown("## List All Services")
        if st.button("List Services"):
            services = list_all_services()
            if services:
                st.write(services)
            else:
                st.warning("No services found.")

        st.markdown("## Delete Password")
        delete_service_name = st.text_input("Service Name to Delete", key="delete_service_name")

        if st.button("Delete Password"):
            delete_password(delete_service_name)
            st.success(f"Password for {delete_service_name} deleted successfully!")

        if st.button("Logout"):
            st.session_state.username = ""
            st.success("Logged out successfully!")

if __name__ == "__main__":
    main()
