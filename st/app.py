# -*- coding: utf-8 -*-
"""
Created on Mon Nov 18 13:51:10 2024

@author: 80816
"""

import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QFileDialog, QLabel, QHBoxLayout
from encryption import AESCipher, RSACipher, SHA256Hasher, save_to_file

class SecureTextApp(QWidget):
    def __init__(self):
        super().__init__()

        # Window settings
        self.setWindowTitle("SecureText - Encryption Tool")
        self.setGeometry(300, 300, 600, 400)
        
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter password")
        
        self.text_input = QTextEdit(self)
        self.text_input.setPlaceholderText("Enter text or upload a file")
        
        self.result_output = QTextEdit(self)
        self.result_output.setPlaceholderText("Encrypted/Decrypted text will appear here")
        self.result_output.setReadOnly(True)

        self.encrypt_button = QPushButton("Encrypt Text", self)
        self.decrypt_button = QPushButton("Decrypt Text", self)
        self.upload_button = QPushButton("Upload Text File", self)
        self.download_button = QPushButton("Download Result", self)

        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.upload_button.clicked.connect(self.upload_file)
        self.download_button.clicked.connect(self.download_result)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(QLabel("Text:"))
        layout.addWidget(self.text_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.upload_button)
        layout.addWidget(self.result_output)
        layout.addWidget(self.download_button)
        
        self.setLayout(layout)

    def encrypt_text(self):
        password = self.password_input.text()
        text = self.text_input.toPlainText()

        if not password or not text:
            self.result_output.setText("Please enter both password and text.")
            return

        aes = AESCipher(password)
        encrypted_text = aes.encrypt(text)
        self.result_output.setText(encrypted_text)

    def decrypt_text(self):
        password = self.password_input.text()
        text = self.text_input.toPlainText()

        if not password or not text:
            self.result_output.setText("Please enter both password and text.")
            return

        aes = AESCipher(password)
        decrypted_text = aes.decrypt(text)
        self.result_output.setText(decrypted_text)

    def upload_file(self):
        options = QFileDialog.Options()
        file, _ = QFileDialog.getOpenFileName(self, "Open Text File", "", "Text Files (*.txt);;All Files (*)", options=options)

        if file:
            with open(file, 'r') as f:
                content = f.read()
                self.text_input.setText(content)

    def download_result(self):
        options = QFileDialog.Options()
        file, _ = QFileDialog.getSaveFileName(self, "Save Result", "", "Text Files (*.txt);;JSON Files (*.json);;All Files (*)", options=options)

        if file:
            content = self.result_output.toPlainText()
            save_to_file(content, file)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureTextApp()
    window.show()
    sys.exit(app.exec_())
