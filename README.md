# GroupProjectCrypt
Secure File Transfer Application with Diffie-Hellman Key Exchange and RSA En-cryption

Introduction:
In today's interconnected world, secure file transfer is a critical aspect of data sharing and communication. It is essential to protect sensitive information from unauthorized access and en-sure the integrity and confidentiality of files during transmission. One common approach to achieving secure file transfer is by using encryption techniques. In this code, we will present a secure file transfer application that combines the Diffie-Hellman key exchange and RSA encryp-tion algorithms.
Overview
The code provides a graphical user interface (GUI) using the Tkinter library, making it us-er-friendly and easy to navigate. The application allows users to select a file, specify the recipi-ent's public key, enter the recipient's hostname and username, and initiate the secure file transfer process.
Modules and Functions
The code utilizes several modules and functions to implement the secure file transfer ap-plication:
1. `os` Module:The `os` module is used to perform file system operations such as reading and writing files. It provides a way to interact with the operating system and handle file-related tasks efficiently.
2. `paramiko` Module:
The `paramiko` module implements the SSH protocol, which enables secure communica-tion and file transfer over a network. It allows the application to establish an SSH connection with the recipient's system and securely transfer files.
3. `getpass` Module:
The `getpass` module provides a secure way to handle password input from the user. It is used in the code to prompt the user for the recipient's username and password when establishing an SSH connection.

4. `cryptography.hazmat` Module:
The `cryptography.hazmat` module is part of the `cryptography` library, which offers cryptographic functionalities. It includes low-level cryptographic primitives and algorithms used in the code, such as Diffie-Hellman key exchange and RSA encryption.

5. `tkinter` Module:
The `tkinter` module is a GUI toolkit that allows the creation of graphical user interfaces. It provides classes and functions to build windows, labels, buttons, entry fields, and handle user interactions. In this code, Tkinter is used to create a user-friendly interface for the secure file trans-fer application.

Key Functions
The code includes several key functions that perform essential tasks:
1. Generating Diffie-Hellman Key Pair:
The `generate_dh_key_pair()` function generates a Diffie-Hellman key pair, consisting of a private key and a corresponding public key. The Diffie-Hellman key exchange is a secure method for establishing a shared secret key between two parties.

2. Saving and Loading Diffie-Hellman Parameters:
The `save_dh_params()` and `load_dh_params()` functions handle saving and loading the Diffie-Hellman parameters to and from files. These parameters include the private key and public key necessary for the key exchange process.
3. Performing Diffie-Hellman Key Exchange:
The `perform_dh_key_exchange()` function performs the Diffie-Hellman key exchange between the sender and the recipient. It takes the sender's private key and the recipient's public key as inputs and derives a shared secret key.
4. Encrypting the File using RSA:The `encrypt_file()` function encrypts a selected file us-ing RSA encryption. It reads the file content, encrypts it using the recipient's public key, and re-turns the encrypted content. RSA encryption provides confidentiality and ensures that only the recipient can decrypt the file.
5. User Input and File Selection:The application provides user-friendly input prompts and file selection dialogs using the Tkinter GUI. Users can select the file to be transferred and specify the recipient's public key, hostname, and username.
To run the code, follow these steps:
1. Install Required Libraries:   Ensure that you have the necessary libraries installed on your system. The code requires the `paramiko`, `cryptography`, and `tkinter` libraries. You can install them using package managers like `pip` or `conda`.
2. Set Up Python Environment: Set up a Python environment on your machine with a compatible version of Python (e.g., Python 3.x).
3. Copy the Code:  Copy the provided code into a Python script file (e.g., `se-cure_file_transfer.py`) using a text editor or an integrated development environment (IDE).
4. Run the Script: Open a terminal or command prompt and navigate to the directory where the script is located.
5. Execute the Script: Run the script by executing the following command: `python se-cure_file_transfer.py`.
6. GUI Application:   After executing the script, a graphical user interface (GUI) window will appear. The window contains input fields and buttons for file selection and other required information.

7. Select the File:  Click the "Select File" button and choose the file you want to transfer.
8. Specify the Recipient's Public Key: Click the "Select Public Key" button and choose the recipient's public key file. This file is required for the RSA encryption process.
9. Enter Recipient's Hostname and Username: Enter the recipient's hostname and username in the respective input fields. These details are necessary for establishing an SSH con-nection with the recipient's system.

10. Start the Transfer:Click the "Start Transfer" button to initiate the secure file transfer process. The application will perform the Diffie-Hellman key exchange, encrypt the file using RSA encryption, and establish an SSH connection to transfer the encrypted file to the recipient.
11. Monitor the Progress:  The application will print relevant messages during the transfer process, indicating the success or failure of each step.
12. Completion: Once the file transfer is completed, a message indicating successful com-pletion will be displayed.
Note: Ensure that you have the necessary permissions and network access rights to per-form the file transfer operation. Additionally, make sure that you have the recipient's correct host-name, username, and public key file for successful encryption and secure transmission.
By following these steps, you will be able to run the code and utilize the secure file trans-fer application with the provided GUI.
Conclusion
The code presented a secure file transfer application that combines the Diffie-Hellman key exchange and RSA encryption algorithms. It offers a user-friendly graphical interface using the Tkinter library, making it easy for users to select files and initiate the secure transfer process. By leveraging cryptographic techniques and secure network communication protocols, the applica-tion ensures the confidentiality and integrity of files during transmission. This code serves as a foundation for building more robust and secure file transfer systems.

