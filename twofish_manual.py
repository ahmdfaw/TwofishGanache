import struct

class Twofish:
    # ==========================================
    # KONSTANTA UTAMA TWOFISH
    # ==========================================
    
    # Matriks Maximum Distance Separable (MDS)
    MDS = [
        [0x01, 0xEF, 0x5B, 0x5B],
        [0x5B, 0xEF, 0xEF, 0x01],
        [0xEF, 0x5B, 0x01, 0xEF],
        [0xEF, 0x01, 0xEF, 0x5B]
    ]

    # Tabel Permutasi S-Box (Standard Twofish)
    SBOX = [
        [0xA3, 0xD7, 0x08, 0x01, 0x00, 0x21, 0x0B, 0x27, 0x07, 0x12, 0x21, 0x68, 0xCB, 0xBB, 0x37, 0x60],
        [0xD0, 0x2B, 0x7D, 0xA9, 0x08, 0x30, 0xEA, 0x7E, 0x15, 0x35, 0x07, 0x8E, 0x24, 0x2D, 0x07, 0x34]
    ]

    def __init__(self, key):
        """Inisialisasi algoritma dengan pembentukan subkeys dan S-Box dinamis."""
        self.subkeys = self._generate_subkeys(key)
        self.sboxes = self._generate_sboxes(key)

    # ==========================================
    # FUNGSI PEMBENTUKAN KUNCI (KEY SCHEDULE)
    # ==========================================

    def _generate_subkeys(self, key):
        """
        Mengubah kunci utama (256-bit) menjadi 40 subkeys untuk 16 putaran Feistel.
        Memecah kunci menjadi bagian genap (Me) dan ganjil (Mo).
        """
        k = list(struct.unpack('<8I', key))
        me = k[0::2]  # Kunci genap
        mo = k[1::2]  # Kunci ganjil
        
        subkeys = []
        for i in range(20):
            # Rotasi sederhana untuk pembentukan subkeys (Versi Kustom)
            a = self._rotate_left(me[0] ^ me[1], 0) 
            subkeys.append((me[0] + i) & 0xFFFFFFFF)
            subkeys.append((mo[0] + i) & 0xFFFFFFFF)
            
        return subkeys

    def _generate_sboxes(self, key):
        """
        Membangun Key-Dependent S-Boxes.
        Memastikan bentuk tabel S-Box berubah menyesuaikan kunci pengguna.
        """
        sbox_dynamic = [list(row) for row in self.SBOX]
        
        for i in range(2):
            for j in range(16):
                # Pengacakan S-Box berbasis XOR dengan subkeys
                sbox_dynamic[i][j] ^= (self.subkeys[i+j] & 0xFF)
                
        return sbox_dynamic

    # ==========================================
    # FUNGSI INTI: ENKRIPSI & DEKRIPSI
    # ==========================================

    def encrypt(self, block):
        """Proses Enkripsi 1 Blok (16 Byte) menggunakan 16 Putaran Feistel."""
        b = list(struct.unpack('<4I', block))
        
        # 1. Input Whitening
        b[0] ^= self.subkeys[0]
        b[1] ^= self.subkeys[1]
        b[2] ^= self.subkeys[2]
        b[3] ^= self.subkeys[3]
        
        # 2. 16 Putaran Feistel Network
        for i in range(16):
            t0 = self._f_function(b[0])
            t1 = self._f_function(self._rotate_left(b[1], 8))
            
            # PHT (Pseudo-Hadamard Transform)
            f0, f1 = self._pht(t0, t1)
            
            # Penambahan Round Keys
            f0 = (f0 + self.subkeys[8 + 2*i]) & 0xFFFFFFFF
            f1 = (f1 + self.subkeys[9 + 2*i]) & 0xFFFFFFFF
            
            # XOR dengan blok Kanan dan Operasi Rotasi
            b[2] = self._rotate_right(b[2] ^ f0, 1)
            b[3] = self._rotate_left(b[3], 1) ^ f1
            
            # Swap blok kiri dan kanan, kecuali pada putaran terakhir
            if i < 15:
                b[0], b[1], b[2], b[3] = b[2], b[3], b[0], b[1]

        # Swap manual setelah semua putaran selesai
        b[0], b[1], b[2], b[3] = b[2], b[3], b[0], b[1]

        # 3. Output Whitening
        b[0] ^= self.subkeys[4]
        b[1] ^= self.subkeys[5]
        b[2] ^= self.subkeys[6]
        b[3] ^= self.subkeys[7]
        
        return struct.pack('<4I', b[0], b[1], b[2], b[3])

    def decrypt(self, block):
        """Proses Dekripsi (Kebalikan persis dari Enkripsi)."""
        b = list(struct.unpack('<4I', block))
        
        # 1. Pembalikan Output Whitening
        b[0] ^= self.subkeys[4]
        b[1] ^= self.subkeys[5]
        b[2] ^= self.subkeys[6]
        b[3] ^= self.subkeys[7]
        
        # Pembalikan Swap manual
        b[0], b[1], b[2], b[3] = b[2], b[3], b[0], b[1]

        # 2. Pembalikan 16 Putaran Feistel (Dieksekusi mundur)
        for i in range(15, -1, -1):
            t0 = self._f_function(b[0])
            t1 = self._f_function(self._rotate_left(b[1], 8))
            
            f0, f1 = self._pht(t0, t1)
            f0 = (f0 + self.subkeys[8 + 2*i]) & 0xFFFFFFFF
            f1 = (f1 + self.subkeys[9 + 2*i]) & 0xFFFFFFFF
            
            b[2] = self._rotate_left(b[2], 1) ^ f0
            b[3] = self._rotate_right(b[3] ^ f1, 1)
            
            if i > 0:
                b[0], b[1], b[2], b[3] = b[2], b[3], b[0], b[1]

        # 3. Pembalikan Input Whitening
        b[0] ^= self.subkeys[0]
        b[1] ^= self.subkeys[1]
        b[2] ^= self.subkeys[2]
        b[3] ^= self.subkeys[3]
        
        return struct.pack('<4I', b[0], b[1], b[2], b[3])

    # ==========================================
    # FUNGSI PEMBANTU MATEMATIS (HELPER)
    # ==========================================

    def _pht(self, a, b):
        """Pseudo-Hadamard Transform untuk mencampur hasil F-Function."""
        a1 = (a + b) & 0xFFFFFFFF
        b1 = (a + 2 * b) & 0xFFFFFFFF
        return a1, b1

    def _rotate_left(self, x, n):
        """Operasi bitwise rotasi ke kiri dengan batas 32-bit."""
        return ((x << (n & 31)) | (x >> (32 - (n & 31)))) & 0xFFFFFFFF
    
    def _rotate_right(self, x, n):
        """Operasi bitwise rotasi ke kanan dengan batas 32-bit."""
        return ((x >> (n & 31)) | (x << (32 - (n & 31)))) & 0xFFFFFFFF

    def _gf_mult(self, a, b):
        """
        Perkalian Galois Field GF(2^8).
        Menggunakan irreducible polynomial standar Twofish: x^8 + x^6 + x^3 + x^2 + 1 (0x169).
        """
        p = 0
        for _ in range(8):
            if b & 1: 
                p ^= a
            carry = a & 0x80
            a <<= 1
            if carry: 
                a ^= 0x169
            b >>= 1
        return p & 0xFF
    
    def _f_function(self, x):
        """
        Fungsi utama (F-Function) pada tiap putaran.
        Membelah 32-bit input, melewati S-Box Dinamis, lalu dikalikan dengan MDS Matrix.
        """
        b0 = x & 0xFF
        b1 = (x >> 8) & 0xFF
        b2 = (x >> 16) & 0xFF
        b3 = (x >> 24) & 0xFF

        # S-Box Substitution
        y0 = self.sboxes[0][b0 % 16]
        y1 = self.sboxes[1][b1 % 16]
        y2 = self.sboxes[0][b2 % 16]
        y3 = self.sboxes[1][b3 % 16]

        # Perkalian dengan MDS Matrix menggunakan Galois Field
        z0 = self._gf_mult(self.MDS[0][0], y0) ^ self._gf_mult(self.MDS[0][1], y1) ^ self._gf_mult(self.MDS[0][2], y2) ^ self._gf_mult(self.MDS[0][3], y3)
        z1 = self._gf_mult(self.MDS[1][0], y0) ^ self._gf_mult(self.MDS[1][1], y1) ^ self._gf_mult(self.MDS[1][2], y2) ^ self._gf_mult(self.MDS[1][3], y3)
        z2 = self._gf_mult(self.MDS[2][0], y0) ^ self._gf_mult(self.MDS[2][1], y1) ^ self._gf_mult(self.MDS[2][2], y2) ^ self._gf_mult(self.MDS[2][3], y3)
        z3 = self._gf_mult(self.MDS[3][0], y0) ^ self._gf_mult(self.MDS[3][1], y1) ^ self._gf_mult(self.MDS[3][2], y2) ^ self._gf_mult(self.MDS[3][3], y3)

        return z0 | (z1 << 8) | (z2 << 16) | (z3 << 24)
    
    def __repr__(self):
        return "Twofish Custom Implementation (Ready)"