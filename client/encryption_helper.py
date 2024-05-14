import base64

from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def generate_session_key(enclave_public_key: X25519PublicKey) -> tuple[bytes, bytes]:
    """
    Generate a temporary session key using ECDH and the public key from attestation document
    This key will be used to encrypt data before sending to enclave
    """

    # Generate a random ECDH private key
    my_private_key = X25519PrivateKey.generate()

    # Get my public key
    my_public_key = my_private_key.public_key()
    my_public_key_bytes = my_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Generate a session key using my private key and enclave's public key
    session_key = my_private_key.exchange(enclave_public_key)

    return (session_key, my_public_key_bytes)

def encrypt(session_key: bytes, plaintext: str) -> str:
    """
    Encrypt message using session key
    """

    # Encrypt the data with the AES session key
    nonce = get_random_bytes(12)
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce = nonce)
    ciphertext, digest = cipher_aes.encrypt_and_digest(str.encode(plaintext))

    # Bundle encrypted session key, nonce, tag and ciphertext for sending to enclave
    return "{}:{}".format(
        base64.b64encode(cipher_aes.nonce).decode(),
        base64.b64encode(ciphertext + digest).decode(),
    )

def decrypt(ciphertext_bundle_b64: str, session_key: bytes):
    ciphertext_parts = ciphertext_bundle_b64.split(":")

    nonce_b64 = ciphertext_parts[0]
    ciphertext_b64 = ciphertext_parts[1]

    nonce = base64.b64decode(nonce_b64)
    full_ciphertext = base64.b64decode(ciphertext_b64)

    ciphertext = full_ciphertext[:-16]
    tag = full_ciphertext[-16:]

    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce = nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()
