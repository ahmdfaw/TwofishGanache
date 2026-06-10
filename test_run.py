from twofish_manual import Twofish
import os

print("=== MENGUJI MESIN TWOFISH MANUAL ===")

# 1. Siapkan Kunci 32-Byte (256-bit)
key = b'KunciRahasiaSkripsiFawwaz2026!!!' 
tf = Twofish(key)
print(f"Status Mesin: {tf}")

# 2. Siapkan 1 Blok Data (Harus pas 16-Byte)
plaintext = b'IniDataRahasia!!'
print(f"\n[+] Plaintext Asli   : {plaintext}")

# 3. Proses Enkripsi
ciphertext = tf.encrypt(plaintext)
print(f"[+] Hasil Ciphertext : {ciphertext.hex().upper()}")

# 4. Proses Dekripsi
decrypted = tf.decrypt(ciphertext)
print(f"[+] Hasil Dekripsi   : {decrypted}")

# 5. Kesimpulan
if plaintext == decrypted:
    print("\n[SUCCESS] LUAR BIASA! Algoritma berhasil mengenkripsi dan mendekripsi dengan sempurna!")
else:
    print("\n[FAILED] Ada yang bocor di putaran Feistel, data tidak kembali.")