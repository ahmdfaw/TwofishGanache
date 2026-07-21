import time
import itertools
import string
import sys
from twofish_manual import Twofish

def pad_key(key_str):
    """Menyesuaikan kunci menjadi 32 byte (256-bit)."""
    return key_str.ljust(32, ' ').encode('utf-8')

def main():
    # 1. SETUP SIMULASI (Ditingkatkan menjadi 3 karakter)
    target_password = "zzz" 
    target_key = pad_key(target_password)
    
    plaintext = b"RahasiaSkripsi!!" 
    
    print("=== SIMULASI BRUTE-FORCE TWOFISH (3 KARAKTER) ===")
    print(f"[*] Target Plaintext : {plaintext}")
    print(f"[*] Target Kunci     : '{target_password}' (Disembunyikan)")
    
    tf = Twofish(target_key)
    ciphertext = tf.encrypt(plaintext)
    print(f"[*] Ciphertext       : {ciphertext.hex()}\n")
    
    print("[*] Memulai serangan Brute-Force (Ini akan memakan waktu lebih lama)...")
    start_time = time.time()
    
    chars = string.ascii_lowercase
    attempts = 0
    found = False
    
    # Mencoba kombinasi panjang kata sandi 1 hingga 3 karakter
    for length in range(1, 4):
        for guess_tuple in itertools.product(chars, repeat=length):
            attempts += 1
            guess_str = ''.join(guess_tuple)
            guess_key = pad_key(guess_str)
            
            # Animasi loading sederhana agar terminal tidak terlihat mati
            if attempts % 1000 == 0:
                sys.stdout.write(f"\r[~] Sedang mencoba iterasi ke-{attempts}...")
                sys.stdout.flush()
            
            tf_guess = Twofish(guess_key)
            try:
                decrypted = tf_guess.decrypt(ciphertext)
                if decrypted == plaintext:
                    end_time = time.time()
                    print(f"\n\n[SUCCESS] Kunci Berhasil Ditembusi: '{guess_str}'")
                    print(f"[!] Jumlah Iterasi/Tebakan : {attempts} kali")
                    print(f"[!] Total Waktu Komputasi  : {end_time - start_time:.4f} detik")
                    found = True
                    break
            except Exception:
                pass
        if found:
            break
            
    if not found:
        print("\n\n[FAILED] Kunci tidak ditemukan.")

if __name__ == "__main__":
    main()