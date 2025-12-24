import hashlib
import timeit
import time  # Digunakan untuk operasi yang lebih lama seperti QKD
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

class SimpleDH:
    """Kelas sederhana untuk mensimulasikan Diffie-Hellman."""
    def __init__(self, p=23, g=5):
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_keys(self):
        self.private_key = get_random_bytes(1)[0] + 1
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, other_public_key):
        self.shared_secret = pow(other_public_key, self.private_key, self.p)

def run_latency_analysis():
    """Fungsi utama untuk menjalankan pengujian latensi komparatif."""
    print("="*60)
    print("--- PENGUJIAN ANALISIS KOMPARATIF LATENSI ---")
    print("="*60)
    
    data_sizes_kb = [1, 16, 128]
    
    print(f"{'Ukuran (KB)':<12} | {'Metode':<15} | {'Waktu Total (ms)':<22}")
    print("-" * 55)
    
    for kb in data_sizes_kb:
        data = get_random_bytes(kb * 1024)
        
        # QKD-AES: Latensi adalah waktu setup QKD + waktu enkripsi AES
        start_time = time.time()
        qkd_res = bb84_simulation(500, eve_present=False, noise_level=0.015)
        qkd_key = derive_aes_key(qkd_res['sifted_key'])
        if qkd_key:
            AES.new(qkd_key, AES.MODE_CBC).encrypt(pad(data, 16))
        end_time = time.time()
        t_qkd_total = (end_time - start_time) * 1000
        print(f"{kb:<12} | {'QKD-AES':<15} | {t_qkd_total:<22.4f}")

        # RSA: Latensi adalah waktu generate kunci + waktu enkripsi
        def rsa_full_cycle():
            key = RSA.generate(2048)
            encryptor = PKCS1_OAEP.new(key.publickey())
            encryptor.encrypt(data[:190]) # Enkripsi sebagian data
        
        t_rsa_total = timeit.timeit(rsa_full_cycle, number=1) * 1000
        print(f"{kb:<12} | {'RSA-2048':<15} | {t_rsa_total:<22.4f}")
        
        # ECC: Latensi adalah waktu generate kunci
        # (karena enkripsi akan menggunakan kunci simetris turunan)
        t_ecc_total = timeit.timeit(lambda: ECC.generate(curve='P-256'), number=10) * 100
        print(f"{kb:<12} | {'ECC (P-256)':<15} | {t_ecc_total:<22.4f}")
        
        # AES: Latensi adalah waktu generate kunci acak + waktu enkripsi
        def aes_full_cycle():
            key = get_random_bytes(16)
            AES.new(key, AES.MODE_CBC).encrypt(pad(data, 16))
        
        t_aes_total = timeit.timeit(aes_full_cycle, number=100) * 10
        print(f"{kb:<12} | {'AES-256':<15} | {t_aes_total:<22.4f}")

        # Diffie-Hellman: Latensi adalah waktu setup pertukaran kunci
        def dh_full_cycle():
            alice = SimpleDH()
            bob = SimpleDH()
            alice.generate_keys()
            bob.generate_keys()
            alice.compute_shared_secret(bob.public_key)
            bob.compute_shared_secret(alice.public_key)

        t_dh_total = timeit.timeit(dh_full_cycle, number=10) * 100
        print(f"{kb:<12} | {'Diffie-Hellman':<15} | {t_dh_total:<22.4f}")
        
        # SHA-256: Latensi adalah waktu hashing
        t_sha_total = timeit.timeit(lambda: hashlib.sha256(data).digest(), number=100) * 10
        print(f"{kb:<12} | {'SHA-256':<15} | {t_sha_total:<22.4f}")
        print("-" * 55)

if __name__ == "__main__":
    run_latency_analysis()