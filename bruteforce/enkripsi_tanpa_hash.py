import os
import sys
import time
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_dir))
from twofish_manual import Twofish

def pad_key(key_str):
    """Menyesuaikan kunci persis 32 byte dengan spasi (TANPA HASH)."""
    key_bytes = key_str.encode('utf-8', errors='ignore')
    return key_bytes[:32].ljust(32, b' ')

def pad_data(data):
    """Menambal data dokumen agar kelipatan 16 byte."""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def main():
    file_asli = "dokumen.pdf" # Pastikan file ini ada!
    file_enkripsi = "target_uji.enc"
    
    # Gunakan password yang ADA di dalam wordlist.txt Anda
    password_mentah = "qwerty123" 
    kunci_32byte = pad_key(password_mentah)
    
    print(f"[*] Membaca {file_asli}...")
    if not os.path.exists(file_asli):
        print(f"[ERROR] {file_asli} tidak ditemukan!")
        return
        
    with open(file_asli, "rb") as f:
        file_bytes = f.read()
        
    padded_data = pad_data(file_bytes)
    tf = Twofish(kunci_32byte)
    
    print(f"[*] Mengenkripsi dokumen dengan kunci (tanpa hash): '{password_mentah}'")
    ciphertext = b""
    
    # Enkripsi murni blok per blok (ECB Mode), tanpa IV acak
    for i in range(0, len(padded_data), 16):
        pt_block = padded_data[i:i+16]
        ciphertext += tf.encrypt(pt_block)
        
    with open(file_enkripsi, "wb") as f:
        f.write(ciphertext)
        
    print(f"[SUCCESS] File berhasil dienkripsi menjadi: {file_enkripsi}")

if __name__ == "__main__":
    main()