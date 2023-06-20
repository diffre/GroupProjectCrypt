import os
import requests
import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from tkinter import Tk, Label, Button, filedialog, messagebox

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as key_file:
        key_file.write(pem)

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        pem = key_file.read()
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
            backend=default_backend()
        )
    return private_key

def encrypt_file(filename, recipient_public_key):
    with open(filename, "rb") as file:
        data = file.read()

    encrypted_data = recipient_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_data

def decrypt_data(data, private_key):
    decrypted_data = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data

def calculate_checksum(data):
    h = hmac.HMAC(data, hashes.SHA256(), backend=default_backend())
    return h.finalize()

def validate_checksum(data, checksum):
    h = hmac.HMAC(data, hashes.SHA256(), backend=default_backend())
    h.verify(checksum)

def sftp_transfer_file(file_path, recipient_public_key_path):
    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Save private key
    private_key_filename = "private_key.pem"
    save_private_key(private_key, private_key_filename)

    # Load recipient's public key
    with open(recipient_public_key_path, "rb") as key_file:
        recipient_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Encrypt file
    encrypted_data = encrypt_file(file_path, recipient_public_key)

    # Calculate checksum
    checksum = calculate_checksum(encrypted_data)

    # Transfer encrypted file and checksum over SFTP
    host = "example.com"  # Replace with your SFTP server host
    username = "your_username"  # Replace with your SFTP server username
    password = "your_password"  # Replace with your SFTP server password
    port = 22  # Replace with your SFTP server port

    transport = paramiko.Transport((host, port))
    transport.connect(username=username, password=password)
    sftp = transport.open_sftp()

    remote_filename = os.path.basename(file_path)
    sftp.putfo(encrypted_data, remote_filename)
    sftp.putfo(checksum, remote_filename + ".checksum")

    sftp.close()
    transport.close()

    # Delete private key file
    os.remove(private_key_filename)

    messagebox.showinfo("Success", "File transfer completed successfully.")

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text=file_path)

def browse_public_key():
    public_key_path = filedialog.askopenfilename()
    if public_key_path:
        public_key_label.config(text=public_key_path)

def transfer_file():
    file_path = file_label.cget("text")
    public_key_path = public_key_label.cget("text")

    if not file_path or not public_key_path:
        messagebox.showerror("Error", "Please select a file and recipient's public key.")
        return

    sftp_transfer_file(file_path, public_key_path)

# Create GUI window Graphical user inteface
window = Tk()
window.title("Secure File Transfer")
window.geometry("600x300")

# File selection label and button
file_label = Label(window, text="Select File:")
file_label.pack()
browse_file_button = Button(window, text="Browse", command=browse_file)
browse_file_button.pack()

# Recipient's public key selection label and button
public_key_label = Label(window, text="Select Recipient's Public Key:")
public_key_label.pack()
browse_public_key_button = Button(window, text="Browse", command=browse_public_key)
browse_public_key_button.pack()

# Transfer file button
transfer_button = Button(window, text="Transfer File", command=transfer_file)
transfer_button.pack()

# Run the GUI
window.mainloop()
