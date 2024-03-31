import sqlite3
import hashlib
import os
import secrets
import hmac
from hashlib import pbkdf2_hmac


class PasswordManager:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                            (id INTEGER PRIMARY KEY, hash TEXT, salt TEXT)''')
        self.conn.commit()

    def _generate_salt(self):
        return secrets.token_hex(16)

    def _hash_password(self, password, salt):
        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
        return hashed_password

    def store_password(self, password):
        salt = self._generate_salt()
        hashed_password = self._hash_password(password, salt)
        self.cursor.execute("INSERT INTO passwords (hash, salt) VALUES (?, ?)", (hashed_password, salt))
        self.conn.commit()

    def verify_password(self, password):
        self.cursor.execute("SELECT hash, salt FROM passwords")
        stored_data = self.cursor.fetchone()
        if stored_data:
            stored_hash, salt = stored_data
            hashed_password = self._hash_password(password, salt)
            return hmac.compare_digest(hashed_password, stored_hash)
        return False

# Przykładowe użycie:
manager = PasswordManager("passwords.db")
manager.store_password("secret_password")
print(manager.verify_password("secret_password"))