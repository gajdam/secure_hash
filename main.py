import sqlite3
import hashlib
import os
import secrets
import hmac
from hashlib import pbkdf2_hmac


class PasswordManager:
    """
        Class for managing passwords in a database, using a simple hashing algorithm and salt.

        Methods:
            __init__(db_name): Initializes the PasswordManager object by creating a connection to the database.
            _generate_salt(): Generates a random salt.
            _hash_password(password, salt): Hashes the password using salt.
            store_password(password): Stores the password in the database.
            verify_password(password): Verifies the password stored in the database.
        """

    def __init__(self, db_name):
        """
            Initializes the PasswordManager object.

            Args:
                db_name (str): Name of the database file.
        """
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                            (id INTEGER PRIMARY KEY, hash TEXT, salt TEXT)''')
        self.conn.commit()

    def _generate_salt(self):
        """
            Generates a random salt.
            Generates a random salt.

            Returns:
                   str: Salt as a string.
               """
        return secrets.token_hex(16)

    def _hash_password(self, password, salt):
        """
                Hashes the password using salt.

                Args:
                    password (str): User's password.
                    salt (str): Salt used for hashing.

                Returns:
                    str: Hashed password as a string.
                """
        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
        return hashed_password

    def store_password(self, password):
        """
                Stores the password in the database.

                Args:
                    password (str): User's password.
                """
        salt = self._generate_salt()
        hashed_password = self._hash_password(password, salt)
        self.cursor.execute("INSERT INTO passwords (hash, salt) VALUES (?, ?)", (hashed_password, salt))
        self.conn.commit()

    def verify_password(self, password):
        """
                Verifies the password stored in the database.

                Args:
                    password (str): User's password.

                Returns:
                    bool: True if the password is correct, False otherwise.
                """
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
