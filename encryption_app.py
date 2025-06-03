from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import gradio as gr


class SymmetricEncryption:
    @staticmethod
    def des_encrypt(key: str, plaintext: str):
        try:
            key_bytes = bytes.fromhex(key)
            key_bytes = key_bytes.ljust(8, b' ')[:8]
            cipher = DES.new(key_bytes, DES.MODE_ECB)
            padded_text = pad(plaintext.encode(), DES.block_size)
            ciphertext = cipher.encrypt(padded_text)
            decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size).decode()
            return ciphertext.hex(), decrypted
        except Exception as e:
            return None, f"Error: {str(e)}"

    @staticmethod
    def aes_encrypt(key: str, plaintext: str):
        try:
            key_bytes = bytes.fromhex(key)
            key_bytes = key_bytes.ljust(16, b' ')[:16]
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            padded_text = pad(plaintext.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_text)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
            return ciphertext.hex(), decrypted
        except Exception as e:
            return None, f"Error: {str(e)}"

    @staticmethod
    def generate_des_key():
        return get_random_bytes(8).hex()

    @staticmethod
    def generate_aes_key():
        return get_random_bytes(16).hex()


class AsymmetricEncryption:
    @staticmethod
    def generate_rsa_keys():
        key = RSA.generate(2048)
        private_key = key.export_key(pkcs=8)  # PKCS#8 format (recommended)
        public_key = key.publickey().export_key()
        return private_key.decode(), public_key.decode()

    @staticmethod
    def rsa_encrypt(public_key_str: str, plaintext: str):
        try:
            key = RSA.import_key(public_key_str)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = cipher.encrypt(plaintext.encode())
            return ciphertext.hex()
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def rsa_decrypt(private_key_str: str, ciphertext_hex: str):
        try:
            key = RSA.import_key(private_key_str)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted = cipher.decrypt(ciphertext).decode()
            return decrypted
        except Exception as e:
            return f"Error: {str(e)}"


def encrypt_decrypt(algorithm, plaintext, key, private_key=None):
    if algorithm == "AES":
        ciphertext, decrypted = SymmetricEncryption.aes_encrypt(key, plaintext)
        return ciphertext, decrypted, None, None
    elif algorithm == "DES":
        ciphertext, decrypted = SymmetricEncryption.des_encrypt(key, plaintext)
        return ciphertext, decrypted, None, None
    elif algorithm == "RSA":
        if not private_key:
            return "RSA private key required for decryption", "", None, None
        ciphertext = AsymmetricEncryption.rsa_encrypt(key, plaintext)
        decrypted = AsymmetricEncryption.rsa_decrypt(private_key, ciphertext)
        return ciphertext, decrypted, private_key, key
    else:
        return "Unsupported Algorithm", "", None, None


def generate_key(algorithm):
    if algorithm == "AES":
        return SymmetricEncryption.generate_aes_key(), None
    elif algorithm == "DES":
        return SymmetricEncryption.generate_des_key(), None
    elif algorithm == "RSA":
        priv, pub = AsymmetricEncryption.generate_rsa_keys()
        return pub, priv  # Return both keys for RSA
    else:
        return "", None


def main():
    with gr.Blocks() as demo:
        gr.Markdown("# Encryption & Decryption Tool")

        algorithm = gr.Dropdown(["AES", "DES", "RSA"], label="Select Algorithm", value="AES")
        plaintext = gr.Textbox(label="Plaintext", lines=3)
        key = gr.Textbox(label="Encryption Key / Public Key (Hex for AES/DES; PEM for RSA)")
        private_key = gr.Textbox(label="RSA Private Key (for RSA decryption only)", visible=False)

        gen_key_btn = gr.Button("Generate Key / Public Key")
        enc_btn = gr.Button("Encrypt & Decrypt")
        clear_btn = gr.Button("Clear")

        ciphertext = gr.Textbox(label="Ciphertext (Hex)", lines=3)
        decrypted_text = gr.Textbox(label="Decrypted Text", lines=3)

        def toggle_private_key_visibility(alg):
            return gr.update(visible=(alg == "RSA"))

        def on_generate_key(alg):
            pub, priv = generate_key(alg)
            if alg == "RSA":
                # Show both keys for RSA
                return pub, priv
            else:
                return pub, ""

        algorithm.change(toggle_private_key_visibility, inputs=algorithm, outputs=private_key)
        gen_key_btn.click(on_generate_key, inputs=algorithm, outputs=[key, private_key])
        enc_btn.click(encrypt_decrypt, inputs=[algorithm, plaintext, key, private_key], outputs=[ciphertext, decrypted_text, private_key, key])
        clear_btn.click(lambda: ("", "", "", "", ""), inputs=None, outputs=[plaintext, key, private_key, ciphertext, decrypted_text])

        demo.launch(share=True)


if __name__ == "__main__":
    main()
