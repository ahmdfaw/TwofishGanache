import time
import sys
import os
import hashlib

# Memastikan Python bisa membaca twofish_manual.py di luar folder bruteforce
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_dir))

from twofish_manual import Twofish

def derive_key_sha256(password: str) -> bytes:
    """Mensimulasikan cara sistem asli membuat kunci menggunakan SHA-256"""
    password_bytes = password.encode('utf-8', errors='ignore')
    return hashlib.sha256(password_bytes).digest()

def main():
    # 1. BACA FILE .ENC DARI HASIL APLIKASI WEB ASLI
    # Pastikan file hasil enkripsi dari web sudah Anda copy ke folder bruteforce
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Mundur satu folder, lalu masuk ke folder 'encrypted'
    file_path = os.path.join(os.path.dirname(current_dir), 'encrypted', 'terenkripsi_PDF_Deid_Deidentification_Hard_0.pdf.enc')
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File '{file_path}' tidak ditemukan!")
        print("Silakan copy file .enc hasil unduhan web ke folder bruteforce ini.")
        return
        
    with open(file_path, "rb") as f:
        # Kita butuh 32 byte pertama!
        # 16 byte pertama = IV (Vektor Inisialisasi)
        # 16 byte kedua = Blok Ciphertext pertama yang berisi header PDF
        header_data = f.read(32)
        
    if len(header_data) < 32:
        print("[ERROR] File terlalu kecil, bukan file enkripsi sistem yang valid.")
        return

    iv = header_data[:16]
    first_ct_block = header_data[16:32]

    # 2. BACA FILE WORDLIST
    wordlist_filename = "wordlist.txt"
    if not os.path.exists(wordlist_filename):
        print(f"[ERROR] File '{wordlist_filename}' tidak ditemukan!")
        return
        
    wordlist = []
    print(f"[*] Membaca kamus '{wordlist_filename}'...")
    with open(wordlist_filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            clean_word = line.strip()
            if clean_word:
                wordlist.append(clean_word)

    print("\n=== PENGUJIAN BRUTE-FORCE PADA SISTEM ENKRIPSI PENUH (SHA256 + CBC) ===")
    print(f"[*] Target File Asli : {file_path}")
    print(f"[*] Total Kata Kamus : {len(wordlist)} kata")
    print(f"[*] IV Terdeteksi    : {iv.hex().upper()}")
    print(f"[*] Ciphertext Blok 1: {first_ct_block.hex().upper()}")
    print("[*] Memulai mesin pembongkar kata sandi tingkat lanjut...\n")

    start_time = time.time()
    attempts = 0
    found = False

    # 3. PROSES PENYERANGAN MURNI DARI KAMUS
    for word in wordlist:
        attempts += 1
        
        # Eksekusi Lapis 1: Hashing kata sandi tebakan
        guess_key = derive_key_sha256(word)

        if attempts % 50 == 0:
            sys.stdout.write(f"\r[~] Mencoba baris ke-{attempts}: '{word}'...   ")
            sys.stdout.flush()

        # Eksekusi Lapis 2 & 3: Inisialisasi Mesin & Proses Dekripsi CBC
        tf_guess = Twofish(guess_key)
        try:
            # A. Dekripsi blok dengan mesin Twofish
            decrypted_block = tf_guess.decrypt(first_ct_block)
            
            # B. XOR hasil dekripsi dengan IV (Sesuai rumus Mode CBC)
            # P_1 = D_K(C_1) XOR IV
            p1_block = bytes(a ^ b for a, b in zip(decrypted_block, iv))
            
            # 4. VERIFIKASI KEBERHASILAN (Cek Magic Bytes PDF)
            if p1_block.startswith(b'%PDF-'):
                end_time = time.time()
                sys.stdout.write("\r" + " " * 60 + "\r") 
                print(f"\n[SUCCESS] BENTENG SISTEM BERHASIL DITEMBUS!")
                print(f"[!] Kunci Asli Ditemukan : '{word}'")
                print(f"[!] Hash Kunci (SHA-256) : {guess_key.hex().upper()}")
                print(f"[!] Jumlah Tebakan Kamus : {attempts} kali")
                print(f"[!] Waktu Komputasi      : {end_time - start_time:.4f} detik")
                found = True
                break
        except Exception:
            pass 

    if not found:
        print("\n\n[FAILED] Serangan gagal. Kunci tidak ada di dalam wordlist.")

if __name__ == "__main__":
    main()