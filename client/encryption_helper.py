import base64

from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def encrypt(enclave_public_key: X25519PublicKey, plaintext: str) -> str:
    """
    Encrypt message using ECDH and the public key from attestation document
    """

    # Generate a random ECDH private key
    my_private_key = X25519PrivateKey.generate()

    # Get my public key
    my_public_key = my_private_key.public_key()
    my_public_key_bytes = my_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Generate a session key using my private key and enclave's public key
    session_key = my_private_key.exchange(enclave_public_key)

    # Encrypt the data with the AES session key
    nonce = get_random_bytes(12)
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce = nonce)
    ciphertext, digest = cipher_aes.encrypt_and_digest(str.encode(plaintext))

    # Return the encrypted session key, nonce, tag and ciphertext
    return "{}:{}:{}".format(
        base64.b64encode(my_public_key_bytes).decode(),
        base64.b64encode(cipher_aes.nonce).decode(),
        base64.b64encode(ciphertext + digest).decode(),
    )
