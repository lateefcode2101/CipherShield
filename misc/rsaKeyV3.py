import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from sympy import isprime

# Define the paths to public and private keys
public_key_path = 'keys/pubKey/public_key.pem'
private_key_path = 'keys/privKey/private_key.pem'

def generate_prime(bit_length):
    while True:
        prime_candidate = random.getrandbits(bit_length)
        prime_candidate |= (1 << bit_length - 1)  # Ensure the number has the full bit length
        prime_candidate |= 1  # Ensure the prime candidate is odd
        if isprime(prime_candidate):
            return prime_candidate

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keys(bit_length):
    p = generate_prime(bit_length // 2)
    q = generate_prime(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return n, e, d, p, q

def rsa_components_to_pem(n, e, d, p, q):
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = mod_inverse(q, p)
    public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, public_numbers=rsa.RSAPublicNumbers(e, n)
    ).private_key(default_backend())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_pem, public_key_pem

def write_keys_to_files(private_key_pem, public_key_pem, private_key_filename=private_key_path, public_key_filename=public_key_path):
    with open(private_key_filename, 'wb') as private_key_file:
        private_key_file.write(private_key_pem)
    with open(public_key_filename, 'wb') as public_key_file:
        public_key_file.write(public_key_pem)

# Generate and save keys
bit_length = 2048
n, e, d, p, q = generate_keys(bit_length)
private_key_pem, public_key_pem = rsa_components_to_pem(n, e, d, p, q)
write_keys_to_files(private_key_pem, public_key_pem)

# Load keys for verification
with open(public_key_path, 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

with open(private_key_path, 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

print('Keys Generated and Loaded Successfully')
