import hashlib

def generate_hash(text):
    encoded = text.encode()

    md5 = hashlib.md5(encoded).hexdigest()
    sha256 = hashlib.sha256(encoded).hexdigest()
    sha512 = hashlib.sha512(encoded).hexdigest()

    print("🔐 Hashes gerados:")
    print(f"  MD5:    {md5}")
    print(f"  SHA256: {sha256}")
    print(f"  SHA512: {sha512}")

if __name__ == "__main__":
    text = input("Digite o texto para gerar o hash: ")
    generate_hash(text)