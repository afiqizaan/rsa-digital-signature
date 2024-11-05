from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate a new RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Get the public key for verification
public_key = private_key.public_key()

# Sample message to sign
message = b"meet me after lunch"

# Hash value (digest) of the message
hash_value = hashes.Hash(hashes.SHA256())
hash_value.update(message)
digest = hash_value.finalize()

# Print the digest in hexadecimal format
print("Digest (hash of message):", digest.hex())

# Sign the hash value (digest) using the private key
signature = private_key.sign(
    digest,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Print the signature in hexadecimal format
print("Signature (in hex):", signature.hex())

# Save the signature to a file
with open("hash_signature.bin", "wb") as signature_file:
    signature_file.write(signature)

print("RSA digital signature generated from hash value and saved.")

# Verify the signature
try:
    public_key.verify(
        signature,
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature verification successful. The message is authentic.")
except Exception as e:
    print("Signature verification failed:", e)

