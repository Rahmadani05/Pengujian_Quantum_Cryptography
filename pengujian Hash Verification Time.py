import hashlib
import timeit
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import math

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

def run_decryption_time_test():
    """Fungsi utama untuk menjalankan pengujian waktu dekripsi."""
    print("="*60)
    print("--- PENGUJIAN WAKTU DEKRIPSI / VERIFIKASI ---")
    print("="*60)
    
    data_sizes_kb = [1, 16, 128]
    
    print(f"{'Ukuran (KB)':<12} | {'Metode':<15} | {'Waktu Dekripsi (ms)':<22}")
    print("-" * 55)
    
    for kb in data_sizes_kb:
        data = get_random_bytes(kb * 1024)
        
        # QKD-AES
        # 1. Setup: Dapatkan kunci dari QKD
        qkd_res = bb84_simulation(500, eve_present=False, noise_level=0.015)
        qkd_key = derive_aes_key(qkd_res['sifted_key'])
        t_qkd_dec_val = "N/A (Kunci Gagal)"
        if qkd_key:
            # 2. Enkripsi data untuk pengujian dekripsi
            cipher_qkd = AES.new(qkd_key, AES.MODE_CBC)
            ct_qkd = cipher_qkd.encrypt(pad(data, 16))
            # 3. Ukur waktu dekripsi
            t_qkd_dec = timeit.timeit(lambda: AES.new(qkd_key, AES.MODE_CBC, iv=cipher_qkd.iv).decrypt(ct_qkd), number=10) * 100
            t_qkd_dec_val = f"{t_qkd_dec:.4f}"
        print(f"{kb:<12} | {'QKD-AES':<15} | {t_qkd_dec_val:<22}")

        # RSA
        # 1. Setup: Buat kunci dan enkripsi data
        rsa_key = RSA.generate(2048)
        encryptor_rsa = PKCS1_OAEP.new(rsa_key.publickey())
        ct_rsa = encryptor_rsa.encrypt(data[:190])
        # 2. Ukur waktu dekripsi
        decryptor_rsa = PKCS1_OAEP.new(rsa_key)
        t_rsa_dec = timeit.timeit(lambda: decryptor_rsa.decrypt(ct_rsa), number=10) * 100
        print(f"{kb:<12} | {'RSA-2048':<15} | {t_rsa_dec:<22.4f}")
        
        # ECC
        # Untuk ECC, pertukaran kunci menghasilkan kunci simetris.
        # Jadi, waktu dekripsinya setara dengan dekripsi AES.
        ecc_symmetric_key = get_random_bytes(16)
        iv_ecc = get_random_bytes(16)
        ct_ecc = AES.new(ecc_symmetric_key, AES.MODE_CBC, iv=iv_ecc).encrypt(pad(data, 16))
        t_ecc_dec = timeit.timeit(lambda: AES.new(ecc_symmetric_key, AES.MODE_CBC, iv=iv_ecc).decrypt(ct_ecc), number=10) * 100
        print(f"{kb:<12} | {'ECC (P-256)':<15} | {t_ecc_dec:<22.4f}")
        
        # AES
        # 1. Setup: Enkripsi data
        aes_key = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        ct_aes = cipher_aes.encrypt(pad(data, 16))
        # 2. Ukur waktu dekripsi
        t_aes_dec = timeit.timeit(lambda: AES.new(aes_key, AES.MODE_CBC, iv=cipher_aes.iv).decrypt(ct_aes), number=10) * 100
        print(f"{kb:<12} | {'AES-256':<15} | {t_aes_dec:<22.4f}")

        # Diffie-Hellman
        print(f"{kb:<12} | {'Diffie-Hellman':<15} | {'N/A':<22}")
        
        # SHA-256
        print(f"{kb:<12} | {'SHA-256':<15} | {'N/A':<22}")
        print("-" * 55)

if __name__ == "__main__":
    run_decryption_time_test()