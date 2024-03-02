import hashlib
from Crypto.Util.number import getPrime, inverse
import Crypto.Random


# ================================================================
# Función leer el numero de bytes
# ================================================================
def read_bytes(filename, num_bytes):
    with open(filename, "rb") as f:
        f.seek(-num_bytes, 2)
        return f.read(num_bytes)


# ================================================================
# Creacion de llaves
# ================================================================
bits = 1024
e = 65537

pA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

nA = pA * qA
phiA = (pA - 1) * (qA - 1)

dA = inverse(e, phiA)

# ================================================================
# Firma
# ================================================================
with open('NDA.pdf', "rb") as f:
    pdf_bytes = f.read()
    pdf_hash = int.from_bytes(hashlib.sha256(pdf_bytes).digest(), "big")
signature = pow(pdf_hash, dA, nA)
print(f'Alice Hash: {pdf_hash}')
signature_bytes = signature.to_bytes(
    (signature.bit_length() + 7) // 8, byteorder="big"
)

with open("NDA.pdf", "ab") as f:
    f.write(signature_bytes)

signature_bytes_from_pdf_AC = read_bytes("NDA.pdf", 256)
signature_int_from_pdf_AC = int.from_bytes(signature_bytes_from_pdf_AC, byteorder="big")

with open("NDA.pdf", "rb") as f:
    pdf_bytes_AC = f.read()[:-256]
    pdf_hash_AC = int.from_bytes(hashlib.sha256(pdf_bytes_AC).digest(), "big")

print(f'Ejercicio 2.-\n')
print(f'AC Hash: {pdf_hash_AC}')
sig_verif_AC = pow(signature_int_from_pdf_AC, e, nA)
print(f'Verificado: {sig_verif_AC == pdf_hash_AC}\n')

# ================================================================
# Quitamos Firma
# ================================================================
with open("NDA.pdf", "wb") as f:
    f.write(pdf_bytes_AC)

pAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)

dAC = inverse(e, phiAC)

signature_ac = pow(pdf_hash_AC, dAC, nAC)

signature_ac_bytes = signature_ac.to_bytes(
    (signature_ac.bit_length() + 7) // 8, byteorder="big"
)
with open("NDA.pdf", "ab") as f:
    f.write(signature_ac_bytes)

signature_bytes_from_pdf_BOB = read_bytes("NDA.pdf", 256)
signature_int_from_pdf_BOB = int.from_bytes(
    signature_bytes_from_pdf_BOB, byteorder="big"
)

with open("NDA.pdf", "rb") as f:
    pdf_bytes_BOB = f.read()[:-256]
    pdf_hash_BOB = int.from_bytes(hashlib.sha256(pdf_bytes_BOB).digest(), "big")

print(f'Bob Hash: {pdf_hash_BOB}')
pdf_hash_verif_bob = pow(signature_ac, e, nAC)
print(f'Verificado: {pdf_hash_verif_bob == pdf_hash_AC}')
