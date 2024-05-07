from cryptography.fernet import Fernet
import psycopg2
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLineEdit, QRadioButton, QHBoxLayout, QMessageBox, QComboBox, QLabel, QGridLayout
from PyQt5.QtCore import Qt

def load_key():
    """Load the previously generated key."""
    return open("secret.key", "rb").read()

key = load_key()
cipher_suite = Fernet(key)

def encrypt_password(password):
    """Encrypt the password."""
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    """Decrypt the password."""
    return cipher_suite.decrypt(encrypted_password).decode()

class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.conn = psycopg2.connect(
            dbname="pw_manager", user="postgres", password="postgres", host="localhost")
        self.cur = self.conn.cursor()
        self.initUI()

    def initUI(self):
        """Initializes the UI components."""
        self.setGeometry(300, 300, 350, 300)
        self.setWindowTitle('Password Manager')

        self.layout = QGridLayout(self)

        # Mode selection using radio buttons
        self.radio_save = QRadioButton("Save Password")
        self.radio_load = QRadioButton("Load Password")
        self.radio_save.setChecked(True)
        self.radio_save.toggled.connect(lambda: self.toggle_mode(True))
        self.radio_load.toggled.connect(lambda: self.toggle_mode(False))

        self.layout.addWidget(self.radio_save, 0, 0)
        self.layout.addWidget(self.radio_load, 0, 1)

        # Adding labels
        self.label_website = QLabel("Website:")
        self.label_username = QLabel("Username:")
        self.label_password = QLabel("Password:")
        
        self.website_field = QLineEdit(self)
        self.username_field = QLineEdit(self)
        self.password = QLineEdit(self)
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Normal)  # Ensure password is not hidden

        self.btn_save_load = QPushButton('Save Password', self)
        self.btn_save_load.clicked.connect(self.save_or_load_password)

        # Adding widgets to layout
        self.layout.addWidget(self.label_website, 1, 0)
        self.layout.addWidget(self.website_field, 1, 1)
        self.layout.addWidget(self.label_username, 2, 0)
        self.layout.addWidget(self.username_field, 2, 1)
        self.layout.addWidget(self.label_password, 3, 0)
        self.layout.addWidget(self.password, 3, 1)
        self.layout.addWidget(self.btn_save_load, 4, 0, 1, 2)

        self.adjust_fields(True)  # Initialize fields for save mode
        self.apply_styles()  # Apply the custom styles

    def apply_styles(self):
        """Applies the custom stylesheet to the widget."""
        self.setStyleSheet("""
            QWidget {
                font-size: 16px;
                color: #F8F8F2;
                background: #282a36;
            }
            QLineEdit, QComboBox {
                border: 2px solid #ff79c6;
                border-radius: 5px;
                padding: 5px;
                background: #44475a;
                color: #f8f8f2;
            }
            QPushButton {
                border: 2px solid #bd93f9;
                border-radius: 10px;
                padding: 5px;
                background: #6272a4;
                color: white;
            }
            QPushButton:hover {
                background-color: #ff79c6;
                color: #282a36;
            }
            QRadioButton {
                font-weight: bold;
                color: #ff79c6;
            }
            QLabel {
                color: #bd93f9;
            }
        """)

    def adjust_fields(self, is_save_mode):
        """Adjusts fields based on the current mode."""
        if is_save_mode:
            self.website_field.deleteLater()
            self.username_field.deleteLater()
            self.website_field = QLineEdit(self)
            self.username_field = QLineEdit(self)
            self.btn_save_load.setText("Save Password")
        else:
            self.website_field.deleteLater()
            self.username_field.deleteLater()
            self.website_field = QComboBox(self)
            self.username_field = QComboBox(self)
            self.website_field.currentIndexChanged.connect(self.update_usernames)
            self.btn_save_load.setText("Load Password")
            self.update_websites()

        self.layout.addWidget(self.website_field, 1, 1)
        self.layout.addWidget(self.username_field, 2, 1)
        self.password.clear()

    def update_websites(self):
        """Updates the website dropdown with available websites."""
        self.website_field.clear()
        self.cur.execute("SELECT DISTINCT website FROM user_passwords")
        websites = self.cur.fetchall()
        for website in websites:
            self.website_field.addItem(website[0])
        self.update_usernames()

    def update_usernames(self):
        """Updates the username dropdown based on the selected website."""
        self.username_field.clear()
        if self.website_field.count() > 0:
            selected_website = self.website_field.currentText()
            self.cur.execute("SELECT DISTINCT username FROM user_passwords WHERE website = %s", (selected_website,))
            usernames = self.cur.fetchall()
            for username in usernames:
                self.username_field.addItem(username[0])

    def toggle_mode(self, is_save_mode):
        """Handles switching between save and load modes."""
        self.adjust_fields(is_save_mode)
        self.password.clear()  # Clear the password field on mode switch

    def save_or_load_password(self):
        """Determines whether to save or load a password based on the mode."""
        if self.btn_save_load.text() == "Save Password":
            self.save_password()
        elif self.btn_save_load.text() == "Load Password" and self.website_field.currentText() and self.username_field.currentText():
            self.load_password()

    def save_password(self):
        """Saves the password into the database."""
        encrypted_password = encrypt_password(self.password.text())
        encoded_password = encrypted_password.decode('utf-8')
        try:
            query = "INSERT INTO user_passwords (website, username, password) VALUES (%s, %s, %s)"
            self.cur.execute(query, (self.website_field.text(), self.username_field.text(), encoded_password))
            self.conn.commit()
            QMessageBox.information(self, 'Success', 'Password saved successfully!')
            self.website_field.clear()
            self.username_field.clear()
            self.password.clear()
        except psycopg2.errors.UniqueViolation:
            QMessageBox.warning(self, 'Error', 'This username already exists for this website.')

    def load_password(self):
        """Loads the password from the database."""
        query = "SELECT password FROM user_passwords WHERE website = %s AND username = %s"
        self.cur.execute(query, (self.website_field.currentText(), self.username_field.currentText()))
        result = self.cur.fetchone()
        if result:
            decrypted_password = decrypt_password(result[0].encode('utf-8'))
            self.password.setText(decrypted_password)
        else:
            QMessageBox.warning(self, 'Not Found', 'No password found for the selected username and website.')

if __name__ == '__main__':
    app = QApplication([])
    ex = PasswordManager()
    ex.show()
    app.exec_()
