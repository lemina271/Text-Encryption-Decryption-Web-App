from flask import Flask, render_template, request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64

app = Flask(__name__)

# AES (Fernet)
aes_key = Fernet.generate_key()
aes_cipher = Fernet(aes_key)

# RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# ChaCha20
chacha_key = ChaCha20Poly1305.generate_key()
chacha_cipher = ChaCha20Poly1305(chacha_key)

def caesar_encrypt(text, shift=3):
    result = ""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    error = ""

    if request.method == "POST":
        text = request.form["text"]
        algo = request.form["algorithm"]
        action = request.form["action"]

        try:
            # AES
            if algo == "aes":
                if action == "encrypt":
                    result = aes_cipher.encrypt(text.encode()).decode()
                else:
                    result = aes_cipher.decrypt(text.encode()).decode()

            # RSA
            elif algo == "rsa":
                if action == "encrypt":
                    encrypted = public_key.encrypt(
                        text.encode(),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    result = encrypted.hex()
                else:
                    decrypted = private_key.decrypt(
                        bytes.fromhex(text),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    result = decrypted.decode()

            # ChaCha20
            elif algo == "chacha":
                nonce = b'0' * 12
                if action == "encrypt":
                    encrypted = chacha_cipher.encrypt(nonce, text.encode(), None)
                    result = encrypted.hex()
                else:
                    decrypted = chacha_cipher.decrypt(nonce, bytes.fromhex(text), None)
                    result = decrypted.decode()

            # Caesar Cipher
            elif algo == "caesar":
                if action == "encrypt":
                    result = caesar_encrypt(text)
                else:
                    result = caesar_decrypt(text)

            # Base64
            elif algo == "base64":
                if action == "encrypt":
                    result = base64.b64encode(text.encode()).decode()
                else:
                    result = base64.b64decode(text.encode()).decode()

        except Exception:
            error = "❌ Invalid input for selected algorithm"

    return render_template("index.html", result=result, error=error)

if __name__ == "__main__":
    app.run(debug=True)
