import random
import string
import hashlib
import base64
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox
import json
import os

class PasswordManager:
    def __init__(self, master_password):
        self.master_password_hash = self._hash_password(master_password)
        self.generated_passwords = {}
        self.biometric_data = None
        self.encrypted_notes = None
        self.password_history = []
        self.cloud_storage_file = "password_manager_data.json"

        # Laden vorhandener Daten aus der Cloud, falls vorhanden
        self.load_data_from_cloud()

    def generate_password(self, service_name, security_level):
        # Passwortgenerierung
        password_pattern = ""

        # Kontextsensitive Passwortgenerierung
        if service_name.lower() == "social_media":
            password_pattern = "SOCIAL" + self._generate_random_string(8)
        elif service_name.lower() == "email":
            password_pattern = "EMAIL" + self._generate_random_string(8)
        else:
            password_pattern = "GENERIC" + self._generate_random_string(8)

        # Intelligente Anpassung
        if security_level == "high":
            password_pattern += self._generate_random_string(4, uppercase=True, digits=True, special_chars=True)
        elif security_level == "medium":
            password_pattern += self._generate_random_string(4, uppercase=True, digits=True)
        else:
            password_pattern += self._generate_random_string(4, uppercase=True)

        self.generated_passwords[service_name] = password_pattern

        # Passworthistorie hinzufügen
        self.password_history.append((service_name, password_pattern))

        # Passwort in die Cloud speichern
        self.save_data_to_cloud()

        return password_pattern

    def rollback_password(self, service_name):
        # Passwort-Rollback-Mechanismus
        # (Hier könnte eine geeignete Logik stehen, um auf vorherige sichere Passwörter zurückzusetzen)

        # Passwort in die Cloud speichern
        self.save_data_to_cloud()

    def encrypt_notes(self, notes, password):
        # Verschlüsselte Notizen mit dynamischem Schlüssel
        key = self._derive_key(password)
        cipher = Fernet(base64.urlsafe_b64encode(key))
        self.encrypted_notes = cipher.encrypt(notes.encode()).decode()

        # Notizen in die Cloud speichern
        self.save_data_to_cloud()

    def decrypt_notes(self, password):
        # Entschlüsseln der Notizen mit dem passenden Schlüssel
        key = self._derive_key(password)
        cipher = Fernet(base64.urlsafe_b64encode(key))
        decrypted_data = cipher.decrypt(self.encrypted_notes.encode()).decode()
        return decrypted_data

    def authenticate_biometric(self, biometric_data):
        # Hier könnte die Logik für die Überprüfung von biometrischen Daten stehen
        pass

    def self_destruct(self):
        # Hier könnte die Logik für die Selbstzerstörungsfunktion stehen
        pass

    def _generate_random_string(self, length, uppercase=False, digits=False, special_chars=False):
        characters = string.ascii_lowercase
        if uppercase:
            characters += string.ascii_uppercase
        if digits:
            characters += string.digits
        if special_chars:
            characters += string.punctuation

        return ''.join(random.choice(characters) for _ in range(length))

    def _hash_password(self, password):
        # Sicheres Hashing-Verfahren verwenden (z.B., bcrypt)
        return hashlib.sha256(password.encode()).digest()

    def _derive_key(self, password):
        # Schlüssel ableiten (kann je nach Sicherheitsanforderungen weiterentwickelt werden)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)

    def save_data_to_cloud(self):
        # Daten in die Cloud speichern (zum Beispiel in einer JSON-Datei)
        data_to_save = {
            "generated_passwords": self.generated_passwords,
            "password_history": self.password_history,
            "biometric_data": self.biometric_data,
            "encrypted_notes": self.encrypted_notes
        }

        with open(self.cloud_storage_file, 'w') as file:
            json.dump(data_to_save, file)

    def load_data_from_cloud(self):
        # Daten aus der Cloud laden, falls vorhanden
        if os.path.exists(self.cloud_storage_file):
            with open(self.cloud_storage_file, 'r') as file:
                saved_data = json.load(file)

            self.generated_passwords = saved_data.get("generated_passwords", {})
            self.password_history = saved_data.get("password_history", [])
            self.biometric_data = saved_data.get("biometric_data")
            self.encrypted_notes = saved_data.get("encrypted_notes")

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("400x300")

        self.password_manager = None

        self.create_widgets()

    def create_widgets(self):
        # Labels
        self.label_master_password = tk.Label(self.master, text="Master Password:")
        self.label_service_name = tk.Label(self.master, text="Service Name:")
        self.label_security_level = tk.Label(self.master, text="Security Level:")
        self.label_notes = tk.Label(self.master, text="Notes:")

        # Entry Widgets
        self.entry_master_password = tk.Entry(self.master, show="*")
        self.entry_service_name = tk.Entry(self.master)
        self.entry_security_level = tk.Entry(self.master)
        self.entry_notes = tk.Entry(self.master)

        # Buttons
        self.button_create_password = tk.Button(self.master, text="Generate Password", command=self.generate_password)
        self.button_encrypt_notes = tk.Button(self.master, text="Encrypt Notes", command=self.encrypt_notes)
        self.button_decrypt_notes = tk.Button(self.master, text="Decrypt Notes", command=self.decrypt_notes)

        # Grid Layout
        self.label_master_password.grid(row=0, column=0, sticky="e")
        self.entry_master_password.grid(row=0, column=1)
        self.label_service_name.grid(row=1, column=0, sticky="e")
        self.entry_service_name.grid(row=1, column=1)
        self.label_security_level.grid(row=2, column=0, sticky="e")
        self.entry_security_level.grid(row=2, column=1)
        self.label_notes.grid(row=3, column=0, sticky="e")
        self.entry_notes.grid(row=3, column=1)

        self.button_create_password.grid(row=4, column=0, columnspan=2, pady=10)
        self.button_encrypt_notes.grid(row=5, column=0, pady=5)
        self.button_decrypt_notes.grid(row=5, column=1, pady=5)

    def generate_password(self):
        master_password = self.entry_master_password.get()
        if master_password:
            self.password_manager = PasswordManager(master_password)
            service_name = self.entry_service_name.get()
            security_level = self.entry_security_level.get()
            generated_password = self.password_manager.generate_password(service_name, security_level)
            messagebox.showinfo("Generated Password", f"Generated Password: {generated_password}")
        else:
            messagebox.showwarning("Error", "Please enter the Master Password.")

    def encrypt_notes(self):
        if self.password_manager:
            notes = self.entry_notes.get()
            master_password = self.entry_master_password.get()
            if notes and master_password:
                self.password_manager.encrypt_notes(notes, master_password)
                messagebox.showinfo("Encryption Success", "Notes encrypted successfully.")
            else:
                messagebox.showwarning("Error", "Please enter Notes and the Master Password.")
        else:
            messagebox.showwarning("Error", "Please generate a password first.")

    def decrypt_notes(self):
        if self.password_manager:
            master_password = self.entry_master_password.get()
            if master_password:
                decrypted_notes = self.password_manager.decrypt_notes(master_password)
                messagebox.showinfo("Decrypted Notes", f"Decrypted Notes: {decrypted_notes}")
            else:
                messagebox.showwarning("Error", "Please enter the Master Password.")
        else:
            messagebox.showwarning("Error", "Please generate a password first.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
