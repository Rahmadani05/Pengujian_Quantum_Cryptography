import hashlib
import timeit
import os
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
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
        return self.shared_secret

def run_performance_tests():
    """Fungsi untuk menjalankan pengujian kinerja komparatif."""
    print("="*85)
    print("--- PENGUJIAN KINERJA KOMPARATIF (WAKTU DALAM MILIDETIK) ---")
    print("="*85)
    
    data_sizes_kb = [1, 16, 128]
    
    header = f"{'Ukuran (KB)':<12} | {'Metode':<15} | {'Waktu Generasi/Setup (ms)':<28} | {'Waktu Dekripsi (ms)':<22}"
    print(header)
    print("-" * len(header))
    
    for kb in data_sizes_kb:
        data = get_random_bytes(kb * 1024)
        
        # QKD-AES
        t_qkd_setup = timeit.timeit(lambda: bb84_simulation(500), number=1) * 1000
        qkd_res = bb84_simulation(500)
        qkd_key = derive_aes_key(qkd_res['sifted_key'])
        t_qkd_dec_val = "N/A"
        if qkd_key:
            cipher_qkd = AES.new(qkd_key, AES.MODE_CBC)
            ct_qkd = cipher_qkd.encrypt(pad(data, 16))
            t_qkd_dec = timeit.timeit(lambda: AES.new(qkd_key, AES.MODE_CBC, iv=cipher_qkd.iv).decrypt(ct_qkd), number=10) * 100
            t_qkd_dec_val = f"{t_qkd_dec:.4f}"
        print(f"{kb:<12} | {'QKD-AES':<15} | {t_qkd_setup:<28.4f} | {t_qkd_dec_val:<22}")

        # RSA
        rsa_key = RSA.generate(2048)
        # Waktu enkripsi
        cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
        t_rsa_enc = timeit.timeit(lambda: cipher_rsa.encrypt(data[:190]), number=10) * 100
        # Waktu dekripsi
        ct_rsa = cipher_rsa.encrypt(data[:190])
        decryptor_rsa = PKCS1_OAEP.new(rsa_key)
        t_rsa_dec = timeit.timeit(lambda: decryptor_rsa.decrypt(ct_rsa), number=10) * 100
        print(f"{kb:<12} | {'RSA-2048':<15} | {t_rsa_enc:<28.4f} | {t_rsa_dec:<22.4f}")
        
        # ECC (disimulasikan sebagai pertukaran kunci + AES)
        # "Waktu Generasi" di sini adalah waktu membuat kunci ECC
        t_ecc_gen = timeit.timeit(lambda: ECC.generate(curve='P-256'), number=10) * 100
        # Waktu dekripsi akan sama dengan AES karena kuncinya simetris
        t_aes_dec_for_ecc = timeit.timeit(lambda: AES.new(get_random_bytes(16), AES.MODE_CBC, iv=get_random_bytes(16)).decrypt(pad(data,16)), number=10) * 100
        print(f"{kb:<12} | {'ECC (P-256)':<15} | {t_ecc_gen:<28.4f} | {t_aes_dec_for_ecc:<22.4f}")
        
        # AES
        aes_key = get_random_bytes(16)
        # Waktu enkripsi
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        t_aes_enc = timeit.timeit(lambda: AES.new(aes_key, AES.MODE_CBC).encrypt(pad(data, 16)), number=10) * 100
        ct_aes = cipher_aes.encrypt(pad(data, 16))
        # Waktu dekripsi
        t_aes_dec = timeit.timeit(lambda: AES.new(aes_key, AES.MODE_CBC, iv=cipher_aes.iv).decrypt(ct_aes), number=10) * 100
        print(f"{kb:<12} | {'AES-256':<15} | {t_aes_enc:<28.4f} | {t_aes_dec:<22.4f}")

        # Diffie-Hellman
        alice = SimpleDH()
        bob = SimpleDH()
        t_dh_setup = timeit.timeit(lambda: (alice.generate_keys(), bob.generate_keys(), alice.compute_shared_secret(bob.public_key)), number=10) * 100
        print(f"{kb:<12} | {'Diffie-Hellman':<15} | {t_dh_setup:<28.4f} | {'N/A':<22}")
        
        # SHA-256
        t_sha_gen = timeit.timeit(lambda: hashlib.sha256(data).digest(), number=10) * 100
        print(f"{kb:<12} | {'SHA-256':<15} | {t_sha_gen:<28.4f} | {'N/A':<22}")
        print("-" * len(header))

if __name__ == "__main__":
    run_performance_tests()