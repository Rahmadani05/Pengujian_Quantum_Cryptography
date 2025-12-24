import hashlib
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

def bb84_simulation(num_bits, eve_present=False, noise_level=0.01):
    simulator = AerSimulator()
    alice_bits = np.random.randint(2, size=num_bits)
    alice_bases = np.random.randint(2, size=num_bits)
    encoded_qubits = []
    for i in range(num_bits):
        qc = QuantumCircuit(1, 1)
        if alice_bits[i] == 1: qc.x(0)
        if alice_bases[i] == 1: qc.h(0)
        encoded_qubits.append(qc)
    if eve_present:
        eve_bases = np.random.randint(2, size=num_bits)
        for i in range(num_bits):
            eve_qc = encoded_qubits[i].copy()
            if eve_bases[i] == 1: eve_qc.h(0)
            eve_qc.measure(0, 0)
            result = simulator.run(eve_qc, shots=1).result()
            measured_bit = int(list(result.get_counts().keys())[0])
            new_qc = QuantumCircuit(1, 1)
            if measured_bit == 1: new_qc.x(0)
            if eve_bases[i] == 1: new_qc.h(0)
            encoded_qubits[i] = new_qc
    bob_bases = np.random.randint(2, size=num_bits)
    bob_measured_bits = []
    for i in range(num_bits):
        qc = encoded_qubits[i]
        if bob_bases[i] == 1: qc.h(0)
        qc.measure(0, 0)
        result = simulator.run(qc, shots=1).result()
        bob_measured_bits.append(int(list(result.get_counts().keys())[0]))
    for i in range(num_bits):
        if np.random.random() < noise_level:
            bob_measured_bits[i] = 1 - bob_measured_bits[i]
    sifted_indices = [i for i in range(num_bits) if alice_bases[i] == bob_bases[i]]
    alice_sifted_key = [alice_bits[i] for i in sifted_indices]
    bob_sifted_key = [bob_measured_bits[i] for i in sifted_indices]
    qber = 0
    if len(alice_sifted_key) > 0:
        mismatches = sum(1 for a, b in zip(alice_sifted_key, bob_sifted_key) if a != b)
        qber = mismatches / len(alice_sifted_key)
    return {"qber": qber, "sifted_key": alice_sifted_key}

def derive_aes_key(key_array):
    if len(key_array) < 128: return None
    key_bits = "".join(map(str, key_array[:128]))
    return int(key_bits, 2).to_bytes(16, 'big')

def calculate_avalanche_effect(data1, data2):
    if len(data1) != len(data2):
        raise ValueError("Data harus memiliki panjang yang sama.")
    xor_result = bytes(a ^ b for a, b in zip(data1, data2))
    diff_bits = sum(bin(byte).count('1') for byte in xor_result)
    total_bits = len(data1) * 8
    avalanche_percentage = (diff_bits / total_bits) * 100
    return diff_bits, total_bits, avalanche_percentage

def run_avalanche_tests():
    """Fungsi utama untuk menjalankan semua pengujian Avalanche Effect."""
    print("="*60)
    print("--- MEMULAI PENGUJIAN AVALANCHE EFFECT ---")
    print("="*60)

    run_id = str(int(time.time())).encode('utf-8')
    base_plaintext = b"Uji Avalanche Effect untuk berbagai algoritma kriptografi."
    plaintext_asli = base_plaintext + b" (ID: " + run_id + b")"
    first_byte_modified = bytes([plaintext_asli[0] ^ 1])
    plaintext_modifikasi = first_byte_modified + plaintext_asli[1:]
    
    print(f"Plaintext Asli      : {plaintext_asli}")
    print(f"Plaintext Modifikasi: {plaintext_modifikasi}\n")
    
    #pengujian algoritma hash & enkripsi
    #SHA-256
    print("\n--- 1. Menguji SHA-256 ---")
    hash_asli = hashlib.sha256(plaintext_asli).digest()
    hash_modifikasi = hashlib.sha256(plaintext_modifikasi).digest()
    diff_bits, total_bits, ae = calculate_avalanche_effect(hash_asli, hash_modifikasi)
    print(f"  Jumlah Bit Berbeda : {diff_bits}/{total_bits}")
    print(f"  Avalanche Effect   : {ae:.2f}%")

    #AES-256
    print("\n--- 2. Menguji AES-256 ---")
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher_aes_asli = AES.new(aes_key, AES.MODE_CBC, iv=iv).encrypt(pad(plaintext_asli, 16))
    cipher_aes_modifikasi = AES.new(aes_key, AES.MODE_CBC, iv=iv).encrypt(pad(plaintext_modifikasi, 16))
    #pastikan panjangnya sama setelah padding
    diff_bits, total_bits, ae = calculate_avalanche_effect(cipher_aes_asli, cipher_aes_modifikasi)
    print(f"  Jumlah Bit Berbeda : {diff_bits}/{total_bits}")
    print(f"  Avalanche Effect   : {ae:.2f}%")
    
    #RSA-2048
    print("\n--- 3. Menguji RSA-2048 ---")
    try:
        rsa_key = RSA.generate(2048)
        encryptor_rsa = PKCS1_OAEP.new(rsa_key.publickey())
        #RSA hanya bisa mengenkripsi data yang lebih kecil dari ukuran kuncinya
        rsa_plaintext_asli = plaintext_asli[:190]
        rsa_plaintext_modifikasi = plaintext_modifikasi[:190]
        
        ct_rsa_asli = encryptor_rsa.encrypt(rsa_plaintext_asli)
        ct_rsa_modifikasi = encryptor_rsa.encrypt(rsa_plaintext_modifikasi)
        diff_bits, total_bits, ae = calculate_avalanche_effect(ct_rsa_asli, ct_rsa_modifikasi)
        print(f"  Jumlah Bit Berbeda : {diff_bits}/{total_bits}")
        print(f"  Avalanche Effect   : {ae:.2f}%")
    except Exception as e:
        print(f"  Gagal menguji RSA: {e}")

    #QKD-AES
    print("\n--- 4. Menguji QKD-AES (dengan Mode CBC untuk hasil ideal) ---")
    print("  Menjalankan simulasi QKD untuk mendapatkan kunci...")
    qkd_result = bb84_simulation(num_bits=500)
    qkd_key = derive_aes_key(qkd_result['sifted_key'])
    if qkd_key:
        print("  Kunci QKD berhasil dibuat. Menguji enkripsi AES...")
        
        # --- PERUBAHAN UTAMA DI SINI ---
        # 1. Ganti mode dari ECB ke CBC yang lebih aman
        # 2. Buat sebuah IV (Initialization Vector) yang akan digunakan untuk kedua enkripsi
        iv = get_random_bytes(16)
        
        cipher_qkd_asli_obj = AES.new(qkd_key, AES.MODE_CBC, iv=iv)
        cipher_qkd_modifikasi_obj = AES.new(qkd_key, AES.MODE_CBC, iv=iv)

        cipher_qkd_asli = cipher_qkd_asli_obj.encrypt(pad(plaintext_asli, 16))
        cipher_qkd_modifikasi = cipher_qkd_modifikasi_obj.encrypt(pad(plaintext_modifikasi, 16))
        
        # Karena CBC bisa menghasilkan panjang yang berbeda jika plaintext berbeda ukuran,
        # kita pastikan membandingkan panjang terpendek untuk keamanan.
        min_len_qkd = min(len(cipher_qkd_asli), len(cipher_qkd_modifikasi))
        
        diff_bits, total_bits, ae = calculate_avalanche_effect(
            cipher_qkd_asli[:min_len_qkd], cipher_qkd_modifikasi[:min_len_qkd]
        )
        print(f"  Jumlah Bit Berbeda : {diff_bits}/{total_bits}")
        print(f"  Avalanche Effect   : {ae:.2f}%") # Hasilnya sekarang akan mendekati 50%
    else:
        print("  Gagal mendapatkan kunci QKD yang cukup panjang untuk pengujian.")

    #penjelasan untuk algoritma yang tidak diuji
    print("\n" + "="*60)
    print("--- Analisis untuk Algoritma yang Tidak Diuji AE ---")
    print("="*60)
    print("ECC dan Diffie-Hellman tidak diuji karena merupakan protokol pertukaran kunci.")
    print("Output mereka (kunci bersama) bergantung pada input acak (kunci privat),")
    print("bukan pada perubahan kecil di sebuah plaintext. Sehingga, konsep Avalanche Effect")
    print("tidak dapat diterapkan secara langsung pada fungsi inti mereka.")


if __name__ == "__main__":
    run_avalanche_tests()