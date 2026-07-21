import time
import itertools
import string
import sys
import os
from twofish_manual import Twofish

def pad_key(key_str):
    """Menyesuaikan kunci menjadi 32 byte (256-bit)."""
    return key_str.ljust(32, ' ').encode('utf-8')

def main():
    # 1. BACA FILE TARGET (.enc)
    # PENTING: Ganti dengan nama file .enc yang Anda enkripsi lewat web!
    file_path = "encrypted\\terenkripsi_Ahmad Fawwaz Jauhar Annufus.pdf.enc" 
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File '{file_path}' tidak ditemukan di folder ini!")
        print("Pastikan Anda sudah memindahkan file .enc hasil unduhan web ke folder proyek.")
        return
        
    with open(file_path, "rb") as f:
        # Baca 16 byte pertama (1 blok) untuk melihat header file
        first_block = f.read(16)

    # 2. BACA FILE WORDLIST
    wordlist_filename = "wordlist.txt"
    if not os.path.exists(wordlist_filename):
        print(f"[ERROR] File '{wordlist_filename}' tidak ditemukan!")
        print("Buat file wordlist.txt dan isi dengan beberapa kata tebakan (misal: admin, root, user).")
        return
        
    wordlist = []
    with open(wordlist_filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            clean_word = line.strip()
            if clean_word:
                wordlist.append(clean_word)

    print("=== PENGUJIAN HYBRID ATTACK PADA FILE .ENC ASLI ===")
    print(f"[*] Target File Asli : {file_path}")
    print(f"[*] Total Kata Kamus : {len(wordlist)} kata")
    print(f"[*] Ciphertext (Hex) : {first_block.hex().upper()}")
    print("[*] Memulai eksekusi Hybrid Attack...\n")

    start_time = time.time()
    bruteforce_chars = string.digits # Kita gunakan kombinasi tambahan berupa angka (0-9)
    attempts = 0
    found = False

    # 3. PROSES PENYERANGAN MENCARI KUNCI
    for word in wordlist:
        # Range 0 sampai 2 (0 = hanya kata dasar, 1 = kata + 1 angka, 2 = kata + 2 angka)
        for length in range(0, 3): 
            for suffix_tuple in itertools.product(bruteforce_chars, repeat=length):
                attempts += 1
                suffix_str = ''.join(suffix_tuple)
                
                # Gabungkan kata dasar + tebakan angka
                guess_str = word + suffix_str
                guess_key = pad_key(guess_str)

                # Indikator loading terminal
                if attempts % 50 == 0:
                    sys.stdout.write(f"\r[~] Mencoba iterasi ke-{attempts}: '{guess_str}'...   ")
                    sys.stdout.flush()

                # Coba proses dekripsi
                tf_guess = Twofish(guess_key)
                try:
                    decrypted_block = tf_guess.decrypt(first_block)
                    
                    # 4. VERIFIKASI KEBERHASILAN (Cek Magic Bytes PDF)
                    # Jika 5 byte pertama adalah '%PDF-', maka kunci 100% akurat!
                    if decrypted_block.startswith(b'%PDF-'):
                        end_time = time.time()
                        sys.stdout.write("\r" + " " * 50 + "\r") # Bersihkan baris loading
                        print(f"\n[SUCCESS] KUNCI DITEMUKAN: '{guess_str}'")
                        print(f"[!] Ditemukan dari kata dasar : '{word}'")
                        print(f"[!] Jumlah Iterasi/Tebakan    : {attempts} kali")
                        print(f"[!] Waktu Komputasi           : {end_time - start_time:.4f} detik")
                        found = True
                        break
                except Exception:
                    pass
            if found:
                break
        if found:
            break

    if not found:
        print("\n\n[FAILED] Kunci tidak ditemukan dalam wordlist maupun kombinasi hibrida.")

if __name__ == "__main__":
    main()