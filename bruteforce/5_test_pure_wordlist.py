import time
import sys
import os
from twofish_manual import Twofish

def pad_key(key_str):
    """Menyesuaikan kunci menjadi 32 byte (256-bit)."""
    key_bytes = key_str.encode('utf-8', errors='ignore')
    return key_bytes[:32].ljust(32, b' ')

def main():
    # 1. SETUP SIMULASI TARGET
    # Target harus ada di dalam file wordlist.txt Anda agar berhasil
    target_password = "kambing" 
    target_key = pad_key(target_password)
    plaintext = b"RahasiaSkripsi!!" 
    
    print("=== SIMULASI PURE DICTIONARY ATTACK (MURNI WORDLIST) ===")
    print(f"[*] Target Plaintext : {plaintext}")
    print(f"[*] Target Kunci     : '{target_password}' (Disembunyikan)")
    
    # Proses enkripsi oleh sistem
    tf = Twofish(target_key)
    ciphertext = tf.encrypt(plaintext)
    print(f"[*] Ciphertext (Hex) : {ciphertext.hex().upper()}\n")
    
    # 2. MEMUAT DATA DARI WORDLIST.TXT
    wordlist_filename = "wordlist.txt"
    
    if not os.path.exists(wordlist_filename):
        print(f"[ERROR] File '{wordlist_filename}' tidak ditemukan!")
        print("Silakan buat file tersebut dan isi dengan beberapa kata per baris.")
        return

    print(f"[*] Membaca isi kamus dari '{wordlist_filename}'...")
    wordlist = []
    
    with open(wordlist_filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            clean_word = line.strip()
            if clean_word:
                wordlist.append(clean_word)
                
    print(f"[*] Berhasil memuat {len(wordlist)} kata tebakan.\n")
    print("[*] Memulai serangan membedah kamus kata sandi...")
    
    start_time = time.time()
    attempts = 0
    found = False
    
    # 3. EKSEKUSI PURE DICTIONARY ATTACK
    for word in wordlist:
        attempts += 1
        guess_key = pad_key(word)
        
        # Indikator di terminal agar terlihat proses berjalannya
        if attempts % 10 == 0:
            sys.stdout.write(f"\r[~] Mencoba baris ke-{attempts}: '{word}'...   ")
            sys.stdout.flush()
            
        tf_guess = Twofish(guess_key)
        try:
            # Mencoba mendekripsi dengan kata dari wordlist
            decrypted = tf_guess.decrypt(ciphertext)
            
            if decrypted == plaintext:
                end_time = time.time()
                sys.stdout.write("\r" + " " * 50 + "\r") # Membersihkan baris loading
                print(f"\n[SUCCESS] Kunci Berhasil Ditembusi: '{word}'")
                print(f"[!] Jumlah Tebakan Kamus : {attempts} kali")
                print(f"[!] Total Waktu Eksekusi : {end_time - start_time:.4f} detik")
                found = True
                break
        except Exception:
            pass # Abaikan error jika kunci salah dan teks gagal didekripsi

    if not found:
        print("\n\n[FAILED] Serangan gagal. Kunci tidak ada di dalam file wordlist.txt.")

if __name__ == "__main__":
    main()