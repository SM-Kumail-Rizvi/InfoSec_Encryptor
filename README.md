# InfoSec Encryptor

A Python-based encryption and decryption tool featuring AES, DES, and RSA algorithms with an intuitive Gradio web interface. Designed for educational and practical use in information security to demonstrate symmetric and asymmetric cryptography concepts, key generation, and secure data handling.

---

## Getting Started

Follow these steps to set up and run the project locally.

### 1. Clone the repository

```bash
git clone https://github.com/SM-Kumail-Rizvi/InfoSec_Encryptor.git
cd InfoSec_Encryptor
```

### 2. Create and activate a conda environment (Python 3.11 recommended)

```bash
conda create -n infosec-env python=3.11 -y
conda activate infosec-env
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python encryption_app.py
```

This will launch the Gradio web interface, and you will see a URL in your terminal (usually `http://localhost:7860`) to access the UI in your browser. Also, the Gradio public URL has also been shown like (`https://10450100e7de9a687d.gradio.live`) which can be shared publically.

---

## Usage

- Select an encryption algorithm: AES, DES, or RSA.
- Enter plaintext to encrypt.
- Generate or enter the required keys:
  - AES/DES keys are hexadecimal strings.
  - RSA keys are PEM-formatted strings.
- Click **Encrypt & Decrypt** to see ciphertext (in hex) and the decrypted plaintext.
- Use the **Clear** button to reset inputs.

---

## Important Cryptography Terms

| Term           | Description                                                                                                  |
|----------------|--------------------------------------------------------------------------------------------------------------|
| **Plaintext**  | The original readable message or data before encryption.                                                     |
| **Ciphertext** | The encrypted, unreadable data produced by applying encryption to plaintext.                                 |
| **AES**        | Advanced Encryption Standard — a symmetric key block cipher that encrypts data in 128-bit blocks.            |
| **DES**        | Data Encryption Standard — an older symmetric key block cipher that encrypts data in 64-bit blocks.          |
| **RSA**        | A public-key (asymmetric) encryption algorithm using a pair of keys: public key (for encryption) and private key (for decryption). |
| **Symmetric Key Encryption**  | Encryption where the same key is used for both encryption and decryption (e.g., AES, DES).                   |
| **Asymmetric Key Encryption** | Encryption that uses a key pair — one key encrypts data, and a different key decrypts it (e.g., RSA).        |
| **Public Key** | The key shared openly to encrypt data in asymmetric encryption systems.                                      |
| **Private Key**| The confidential key used to decrypt data in asymmetric encryption systems.                                  |

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
