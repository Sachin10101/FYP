from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import secrets
import hashlib


class SecurityContext(dict):
    """A dictionary that also provides method access to its keys"""
    def __init__(self, *args, **kwargs):
        super(SecurityContext, self).__init__(*args, **kwargs)
        
    def get_public_key(self):
        """Return the public key"""
        return self.get('public_key')
        
    def get_private_key(self):
        """Return the private key"""
        return self.get('private_key')
        
    def decrypt_message(self, encrypted_message):
        """Decrypt a message using the private key"""
        return decrypt_message(self.get('private_key'), encrypted_message)

def generate_key_pair():
    """Generate RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Return a SecurityContext object instead of a plain dictionary
    return SecurityContext({
        'private_key': private_pem.decode('utf-8'),
        'public_key': public_pem.decode('utf-8')
    })

def encrypt_message(public_key_pem, message):
    """Encrypt message with recipient's public key"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(private_key_pem, encrypted_message):
    """Decrypt message with private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

def sign_message(private_key_pem, message):
    """Sign a message with private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, message, signature):
    """Verify a message signature with public key"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    try:
        public_key.verify(
            base64.b64decode(signature),
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# AES Encryption Functions
def generate_aes_key():
    """Generate a secure random AES-256 key"""
    return os.urandom(32)  # 256 bits

def derive_key_from_password(password, salt=None):
    """Derive an AES key from a password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    # Use PBKDF2 with 100,000 iterations for key derivation
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    return key, salt

def aes_encrypt(data, key):
    """Encrypt data using AES-256-GCM"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate a random 96-bit IV (recommended for GCM)
    iv = os.urandom(12)
    
    # Create an encryptor object
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Return IV, ciphertext, and tag as a base64 encoded string
    result = base64.b64encode(iv + tag + ciphertext).decode('utf-8')
    return result

def aes_decrypt(encrypted_data, key):
    """Decrypt data using AES-256-GCM"""
    # Decode the base64 encoded string
    data = base64.b64decode(encrypted_data)
    
    # Extract IV (first 12 bytes), tag (next 16 bytes), and ciphertext
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    
    # Create a decryptor object
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Return the plaintext as a string
    return plaintext.decode('utf-8')

def hybrid_encrypt(message, recipient_public_key_pem):
    """
    Hybrid encryption: Use RSA to encrypt an AES key, then use AES to encrypt the actual message
    This is more efficient for larger messages
    """
    # Generate a random AES key
    aes_key = generate_aes_key()
    
    # Encrypt the message with AES
    encrypted_message = aes_encrypt(message, aes_key)
    
    # Encrypt the AES key with RSA
    public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Base64 encode the encrypted key
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
    
    # Return both the encrypted key and the encrypted message
    return {
        'encrypted_key': encrypted_key_b64,
        'encrypted_message': encrypted_message
    }

def hybrid_decrypt(encrypted_data, private_key_pem):
    """
    Hybrid decryption: Use RSA to decrypt the AES key, then use AES to decrypt the message
    """
    # Extract the encrypted key and message
    encrypted_key_b64 = encrypted_data['encrypted_key']
    encrypted_message = encrypted_data['encrypted_message']
    
    # Decrypt the AES key with RSA
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    aes_key = private_key.decrypt(
        base64.b64decode(encrypted_key_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt the message with AES
    decrypted_message = aes_decrypt(encrypted_message, aes_key)
    
    return decrypted_message

def encrypt_file(file_path, recipient_public_key_pem):
    """Encrypt a file using hybrid encryption"""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Generate a random AES key
    aes_key = generate_aes_key()
    
    # Generate a random IV
    iv = os.urandom(12)
    
    # Create an encryptor object
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Encrypt the file data
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Encrypt the AES key with RSA
    public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return the encrypted key, IV, tag, and ciphertext
    return {
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_file(encrypted_data, private_key_pem):
    """Decrypt a file using hybrid encryption"""
    # Extract the encrypted key, IV, tag, and ciphertext
    encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
    iv = base64.b64decode(encrypted_data['iv'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    # Decrypt the AES key with RSA
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Create a decryptor object
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

def generate_secure_token(length=32):
    """Generate a cryptographically secure random token"""
    return secrets.token_hex(length)
