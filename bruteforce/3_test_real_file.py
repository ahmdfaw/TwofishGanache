import time
import itertools
import string
import sys
from twofish_manual import Twofish

def pad_key(key_str):
    """Menyesuaikan kunci menjadi 32 byte (256-bit)."""
    return key_str.ljust(32, ' ').encode('utf-8')

def main():
    # 1. BACA FILE HASIL DARI SISTEM WEB ANDA
    # Ubah nama file ini dengan nama file .enc yang Anda download dari web!
    file_path = "encrypted\\terenkripsi_E_2200018149_Ahmad Fawwaz.pdf.enc" 
    
    try:
        with open(file_path, "rb") as f:
            # Kita hanya perlu membaca 16 byte (1 blok) pertama saja untuk mengecek header PDF
            first_block = f.read(16)
    except FileNotFoundError:
        print(f"[ERROR] File '{file_path}' tidak ditemukan di folder ini!")
        print("Silakan enkripsi sebuah file PDF di web, masukkan kunci 2-3 huruf (misal: 'ab'), lalu pindahkan file .enc-nya ke sini.")
        return

    print("=== PENGUJIAN BRUTE-FORCE PADA FILE .ENC ASLI ===")
    print(f"[*] Target File Asli : {file_path}")
    print(f"[*] Ciphertext Blok 1: {first_block.hex().upper()}")
    print("[*] Memulai mesin pembongkar kata sandi...\n")
    
    start_time = time.time()
    chars = string.ascii_lowercase
    attempts = 0
    found = False
    
    # 2. PROSES BRUTE FORCE PADA FILE
    for length in range(1, 4): # Mencoba 1 sampai 3 huruf
        for guess_tuple in itertools.product(chars, repeat=length):
            attempts += 1
            guess_str = ''.join(guess_tuple)
            guess_key = pad_key(guess_str)
            
            if attempts % 500 == 0:
                sys.stdout.write(f"\r[~] Mencoba iterasi ke-{attempts}: '{guess_str}'...")
                sys.stdout.flush()
            
            tf_guess = Twofish(guess_key)
            try:
                decrypted_block = tf_guess.decrypt(first_block)
                
                # 3. VERIFIKASI KEBERHASILAN (MAGIC BYTES PDF)
                # Jika 5 byte pertama adalah '%PDF-', maka file berhasil ditembus!
                if decrypted_block.startswith(b'%PDF-'):
                    end_time = time.time()
                    sys.stdout.write("\r" + " " * 50 + "\r")
                    print(f"\n[SUCCESS] KUNCI DITEMUKAN: '{guess_str}'")
                    print(f"[!] Jumlah Iterasi/Tebakan : {attempts} kali")
                    print(f"[!] Waktu Komputasi        : {end_time - start_time:.4f} detik")
                    found = True
                    break
            except Exception:
                pass
        if found:
            break
            
    if not found:
        print("\n\n[FAILED] Kunci tidak ditemukan dalam batas pencarian.")

if __name__ == "__main__":
    main()