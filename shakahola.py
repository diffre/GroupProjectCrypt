import os
import getpass
import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import tkinter as tk
from tkinter import filedialog

# Define the function for file encryption
def encrypt_file(file_path, recipient_public_key_path, recipient_hostname, recipient_username, recipient_password):
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the recipient's machine
        ssh.connect(recipient_hostname, username=recipient_username, password=recipient_password)

        # Open an SFTP session
        sftp = ssh.open_sftp()

        try:
            # Extract the file name from the file path
            file_name = os.path.basename(file_path)

            # Determine the destination path on the recipient's machine
            remote_path = "/path/to/destination/" + file_name

            # Generate an RSA key pair
            sender_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            sender_public_key = sender_private_key.public_key()

            # Serialize the sender's public key
            sender_public_key_pem = sender_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Save the sender's public key to a file
            with sftp.open(recipient_public_key_path, "wb") as public_key_file:
                public_key_file.write(sender_public_key_pem)

            # Encrypt the file using the recipient's public key
            with open(file_path, "rb") as src_file:
                with sftp.open(remote_path, "wb") as dest_file:
                    recipient_public_key = serialization.load_pem_public_key(
                        sftp.open(recipient_public_key_path, "rb").read(),
                        backend=default_backend()
                    )
                    encrypted_file = recipient_public_key.encrypt(
                        src_file.read(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    dest_file.write(encrypted_file)

            print("File sent successfully!")
        finally:
            # Close the SFTP session
            sftp.close()
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as e:
        print("SSH connection error:", str(e))
    except paramiko.sftp.SFTPError as e:
        print("SFTP error:", str(e))
    finally:
        # Close the SSH connection
        ssh.close()


# Define the function for file decryption
def decrypt_file(file_path, recipient_private_key_path, sender_hostname, sender_username, sender_password):
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the sender's machine
        ssh.connect(sender_hostname, username=sender_username, password=sender_password)

        # Open an SFTP session
        sftp = ssh.open_sftp()

        try:
            # Determine the source path on the sender's machine
            remote_path = "/path/to/source/" + file_path

            # Load the recipient's private key
            recipient_private_key = serialization.load_pem_private_key(
                open(recipient_private_key_path, "rb").read(),
                password=None,
                backend=default_backend()
            )

            # Decrypt the file using the recipient's private key
            with sftp.open(remote_path, "rb") as src_file:
                with open(file_path, "wb") as dest_file:
                    encrypted_file = src_file.read()
                    decrypted_file = recipient_private_key.decrypt(
                        encrypted_file,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    dest_file.write(decrypted_file)

            print("File received successfully!")
        finally:
            # Close the SFTP session
            sftp.close()
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as e:
        print("SSH connection error:", str(e))
    except paramiko.sftp.SFTPError as e:
        print("SFTP error:", str(e))
    finally:
        # Close the SSH connection
        ssh.close()


# Define the function for sending a file
def send_file():
    file_path = filedialog.askopenfilename()
    recipient_public_key_path = filedialog.askopenfilename()

    recipient_hostname = recipient_hostname_entry.get()
    recipient_username = recipient_username_entry.get()
    recipient_password = recipient_password_entry.get()

    encrypt_file(file_path, recipient_public_key_path, recipient_hostname, recipient_username, recipient_password)


# Define the function for receiving a file
def receive_file():
    file_path = filedialog.askdirectory()
    recipient_private_key_path = filedialog.askopenfilename()

    sender_hostname = sender_hostname_entry.get()
    sender_username = sender_username_entry.get()
    sender_password = sender_password_entry.get()

    decrypt_file(file_path, recipient_private_key_path, sender_hostname, sender_username, sender_password)


# Define the function for selecting the sender's key
def select_sender_key():
    sender_key_path = filedialog.askopenfilename()
    sender_key_entry.delete(0, tk.END)
    sender_key_entry.insert(tk.END, sender_key_path)


# Define the function for selecting the receiver's key
def select_receiver_key():
    receiver_key_path = filedialog.askopenfilename()
    receiver_key_entry.delete(0, tk.END)
    receiver_key_entry.insert(tk.END, receiver_key_path)


# Main program
def main():
    window = tk.Tk()
    window.title("File Encryption/Decryption")
    window.geometry("900x500")

    recipient_hostname_label = tk.Label(window, text="Recipient's Hostname:")
    recipient_hostname_label.pack()
    recipient_hostname_entry = tk.Entry(window)
    recipient_hostname_entry.pack()

    recipient_username_label = tk.Label(window, text="Recipient's Username:")
    recipient_username_label.pack()
    recipient_username_entry = tk.Entry(window)
    recipient_username_entry.pack()

    recipient_password_label = tk.Label(window, text="Recipient's Password:")
    recipient_password_label.pack()
    recipient_password_entry = tk.Entry(window, show="*")
    recipient_password_entry.pack()

    sender_hostname_label = tk.Label(window, text="Sender's Hostname:")
    sender_hostname_label.pack()
    sender_hostname_entry = tk.Entry(window)
    sender_hostname_entry.pack()

    sender_username_label = tk.Label(window, text="Sender's Username:")
    sender_username_label.pack()
    sender_username_entry = tk.Entry(window)
    sender_username_entry.pack()

    sender_password_label = tk.Label(window, text="Sender's Password:")
    sender_password_label.pack()
    sender_password_entry = tk.Entry(window, show="*")
    sender_password_entry.pack()

    sender_key_label = tk.Label(window, text="Sender's Key:")
    sender_key_label.pack()
    sender_key_entry = tk.Entry(window)
    sender_key_entry.pack()

    sender_key_button = tk.Button(window, text="Select Key", command=select_sender_key)
    sender_key_button.pack()

    receiver_key_label = tk.Label(window, text="Receiver's Key:")
    receiver_key_label.pack()
    receiver_key_entry = tk.Entry(window)
    receiver_key_entry.pack()

    receiver_key_button = tk.Button(window, text="Select Key", command=select_receiver_key)
    receiver_key_button.pack()

    send_button = tk.Button(window, text="Send File", command=send_file)
    send_button.pack()

    receive_button = tk.Button(window, text="Receive File", command=receive_file)
    receive_button.pack()

    window.mainloop()


if __name__ == "__main__":
    main()
