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
    # 1. SETUP SIMULASI
    target_password = "ahmad" 
    target_key = pad_key(target_password)
    plaintext = b"RahasiaSkripsi!!" 
    
    print("=== SIMULASI HYBRID ATTACK DENGAN WORDLIST ===")
    print(f"[*] Target Plaintext : {plaintext}")
    print(f"[*] Target Kunci     : '{target_password}' (Disembunyikan)")
    
    tf = Twofish(target_key)
    ciphertext = tf.encrypt(plaintext)
    print(f"[*] Ciphertext       : {ciphertext.hex()}\n")
    
    # 2. MEMUAT DATA DARI WORDLIST.TXT
    wordlist_filename = "wordlist.txt"
    
    # Pengecekan apakah file ada di folder
    if not os.path.exists(wordlist_filename):
        print(f"[ERROR] File '{wordlist_filename}' tidak ditemukan!")
        print("Silakan buat file tersebut atau unduh dari GitHub dan simpan di folder proyek.")
        return

    print(f"[*] Membaca data kamus dari {wordlist_filename}...")
    wordlist = []
    
    # Membuka file dengan mode read, mengabaikan karakter error bawaan file dari internet
    with open(wordlist_filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            # line.strip() berguna untuk menghapus spasi atau enter kosong di akhir kata
            clean_word = line.strip()
            if clean_word:
                wordlist.append(clean_word)
                
    print(f"[*] Berhasil memuat {len(wordlist)} kata dasar dari file.\n")

    bruteforce_chars = string.digits 
    
    print("[*] Memulai Serangan Hibrida (Wordlist + Brute-Force Akhiran)...")
    start_time = time.time()
    
    attempts = 0
    found = False
    
    # 3. EKSEKUSI HYBRID ATTACK
    for word in wordlist:
        for length in range(1, 3):
            for suffix_tuple in itertools.product(bruteforce_chars, repeat=length):
                attempts += 1
                suffix_str = ''.join(suffix_tuple)
                guess_str = word + suffix_str
                guess_key = pad_key(guess_str)
                
                if attempts % 100 == 0:
                    sys.stdout.write(f"\r[~] Mencoba iterasi ke-{attempts}: {guess_str}...   ")
                    sys.stdout.flush()
                
                tf_guess = Twofish(guess_key)
                try:
                    decrypted = tf_guess.decrypt(ciphertext)
                    if decrypted == plaintext:
                        end_time = time.time()
                        sys.stdout.write("\r" + " " * 50 + "\r")
                        print(f"\n[SUCCESS] Kunci Berhasil Ditembusi: '{guess_str}'")
                        print(f"[!] Ditemukan dari kata dasar  : '{word}'")
                        print(f"[!] Jumlah Iterasi/Tebakan     : {attempts} kali")
                        print(f"[!] Total Waktu Komputasi      : {end_time - start_time:.4f} detik")
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