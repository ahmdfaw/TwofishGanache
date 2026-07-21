import time
import sys
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_dir))
from twofish_manual import Twofish

def pad_key(key_str):
    """
    Fungsi penyesuai kunci ANTI-CRASH.
    Memotong paksa kata sandi yang kepanjangan di wordlist menjadi 32 byte,
    dan menambal yang kependekan dengan spasi.
    """
    key_bytes = key_str.encode('utf-8', errors='ignore')
    return key_bytes[:32].ljust(32, b' ')

def main():
    # 1. BACA FILE TARGET HASIL ENKRIPSI SEDERHANA
    file_path = "target_uji.enc" 

    # current_dir = os.path.dirname(os.path.abspath(__file__))
    # file_path = os.path.join(os.path.dirname(current_dir), 'encrypted', 'terenkripsi_PDF_Deid_Deidentification_Hard_1.pdf.enc')
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File '{file_path}' tidak ditemukan!")
        return
        
    with open(file_path, "rb") as f:
        # Kita hanya perlu 16 byte pertama (1 blok) untuk mencari '%PDF-'
        first_block = f.read(16)

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

    print("\n=== PENGUJIAN PURE DICTIONARY ATTACK PADA FILE .ENC ===")
    print(f"[*] Target File Asli : {file_path}")
    print(f"[*] Total Kata Kamus : {len(wordlist)} kata")
    print(f"[*] Ciphertext Blok 1: {first_block.hex().upper()}")
    print("[*] Memulai mesin pembongkar kata sandi...\n")

    start_time = time.time()
    attempts = 0
    found = False

    # 3. PROSES PENYERANGAN MURNI DARI KAMUS
    for word in wordlist:
        attempts += 1
        guess_key = pad_key(word)

        # Indikator loading (dicetak setiap kelipatan 50 agar terminal tidak lag)
        if attempts % 50 == 0:
            sys.stdout.write(f"\r[~] Mencoba baris ke-{attempts}: '{word}'...   ")
            sys.stdout.flush()

        tf_guess = Twofish(guess_key)
        try:
            # Dekripsi 1 blok pertama
            decrypted_block = tf_guess.decrypt(first_block)
            
            # 4. VERIFIKASI KEBERHASILAN (Cek Magic Bytes PDF)
            if decrypted_block.startswith(b'%PDF-'):
                end_time = time.time()
                sys.stdout.write("\r" + " " * 60 + "\r") # Bersihkan layar loading
                print(f"\n[SUCCESS] KUNCI DITEMUKAN: '{word}'")
                print(f"[!] File terbukti merupakan dokumen PDF asli.")
                print(f"[!] Jumlah Tebakan Kamus : {attempts} kali")
                print(f"[!] Waktu Komputasi      : {end_time - start_time:.4f} detik")
                found = True
                break
        except Exception:
            pass # Abaikan jika gagal dekripsi

    if not found:
        print("\n\n[FAILED] Serangan gagal. Kunci tidak ada di dalam wordlist.")

if __name__ == "__main__":
    main()