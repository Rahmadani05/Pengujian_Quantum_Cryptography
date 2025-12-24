import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import threading
import math
import time

def bb84_simulation(num_bits, eve_present=False, noise_level=0.05):
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
    
    #simulasi Noise pada Kanal Kuantum
    for i in range(num_bits):
        if np.random.random() < noise_level:
            bob_measured_bits[i] = 1 - bob_measured_bits[i]

    #proses Sifting
    sifted_indices = [i for i in range(num_bits) if alice_bases[i] == bob_bases[i]]
    alice_sifted_key = [alice_bits[i] for i in sifted_indices]
    bob_sifted_key = [bob_measured_bits[i] for i in sifted_indices]

    #implememtasi rumus - QBER (Quantum Bit Error Rate)
    #menghitung rasio antara bit yang salah dengan total bit setelah sifting.
    #A = mismatches, B = len(alice_sifted_key)
    qber = 0
    if len(alice_sifted_key) > 0:
        mismatches = sum(1 for a, b in zip(alice_sifted_key, bob_sifted_key) if a != b)
        qber = mismatches / len(alice_sifted_key)

    return {"qber": qber, "sifted_key": alice_sifted_key}

#fungsi untuk menghitung SKR (Secure Key Rate)
def calculate_skr(qber):
    """
    Menghitung Secure Key Rate (R) berdasarkan nilai QBER.
    """
    if qber == 0:
        #H2(0) adalah 0. Jika tidak ada error, 100% sifted key bisa jadi secure key.
        return 1.0
    if qber >= 0.5:
        #jika error lebih dari 50%, tidak ada informasi yang bisa diselamatkan.
        return 0.0

    #implementasi rumus entropi shannon binner H2(x)
    #rumus: H2(x) = -x*log2(x) - (1-x)*log2(1-x)
    h2_qber = -qber * math.log2(qber) - (1 - qber) * math.log2(1 - qber)
    
    #implementasi rumus - Secure Key Rate (SKR) Sederhana
    #rumus: R = 1 - 2*H2(QBER)
    skr = 1 - (2 * h2_qber)
    return max(0, skr)

#mengubah array bit menjadi kunci AES 16-byte
def derive_aes_key(key_array):
    if len(key_array) < 128: return None
    key_bits = "".join(map(str, key_array[:128]))
    return int(key_bits, 2).to_bytes(16, 'big')

#enkripsi menggunakan AES mode CBC
def encrypt_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return ciphertext, cipher.iv

 #dekripsi menggunakan AES mode CBC
def decrypt_aes(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_bytes = cipher.decrypt(ciphertext)
    return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

def run_performance_test():
    print("\n White Box Testing : Uji Performa")
    bit_counts = [250, 500, 1000, 2000, 5000]
    print(f"{'Jumlah Bit':<15} | {'Waktu Eksekusi (detik)':<25}")
    print("-" * 45)

    for bits in bit_counts:
        start_time = time.time()
        bb84_simulation(num_bits=bits, eve_present=True, noise_level=0.01)
        end_time = time.time()
        duration = end_time - start_time
        print(f"{bits:<15} | {duration:<25.4f}")

class QKDvsModernApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simulasi Kriptografi Kuantum vs Modern")
        self.geometry("800x780")

        self.eve_present_var = tk.BooleanVar()
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.LabelFrame(main_frame, text="Input Pesan", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        self.msg_input = scrolledtext.ScrolledText(input_frame, height=3)
        self.msg_input.pack(fill=tk.X, expand=True)
        self.msg_input.insert(tk.END, " ")
        ttk.Checkbutton(input_frame, text="Aktifkan Penyadapan (Eve)", variable=self.eve_present_var).pack(pady=5)

        encryption_scenarios_frame = ttk.Frame(main_frame)
        encryption_scenarios_frame.pack(fill=tk.X, pady=5)
        
        modern_frame = ttk.LabelFrame(encryption_scenarios_frame, text="Skenario 1: Modern (AES Pre-Shared Key)", padding="10")
        modern_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(modern_frame, text="Jalankan Enkripsi Modern", command=self.run_modern_encryption).pack(pady=5)
        self.modern_status = ttk.Label(modern_frame, text="Status: Menunggu", font=("Helvetica", 10, "italic"))
        self.modern_status.pack()

        quantum_frame = ttk.LabelFrame(encryption_scenarios_frame, text="Skenario 2: Quantum-Secured (QKD+AES)", padding="10")
        quantum_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        ttk.Button(quantum_frame, text="Jalankan Enkripsi Kuantum", command=self.run_quantum_encryption).pack(pady=5)
        self.quantum_status = ttk.Label(quantum_frame, text="Status: Menunggu", font=("Helvetica", 10, "italic"))
        self.quantum_status.pack()
        self.qber_label = ttk.Label(quantum_frame, text="QBER: -")
        self.qber_label.pack()
        self.skr_label = ttk.Label(quantum_frame, text="SKR: -")
        self.skr_label.pack()

        results_frame = ttk.LabelFrame(main_frame, text="Log Hasil Enkripsi", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.results_text = scrolledtext.ScrolledText(results_frame, height=8, state=tk.DISABLED)
        self.results_text.pack(fill=tk.BOTH, expand=True)

        manual_decrypt_frame = ttk.LabelFrame(main_frame, text="Dekripsi Manual", padding="10")
        manual_decrypt_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(manual_decrypt_frame, text="Kunci (hex):").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.manual_key_entry = ttk.Entry(manual_decrypt_frame, width=70)
        self.manual_key_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        ttk.Label(manual_decrypt_frame, text="IV (hex):").grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.manual_iv_entry = ttk.Entry(manual_decrypt_frame, width=70)
        self.manual_iv_entry.grid(row=1, column=1, padx=5, pady=2, sticky=tk.EW)
        ttk.Label(manual_decrypt_frame, text="Ciphertext (hex):").grid(row=2, column=0, padx=5, pady=2, sticky=tk.W)
        self.manual_ciphertext_entry = ttk.Entry(manual_decrypt_frame, width=70)
        self.manual_ciphertext_entry.grid(row=2, column=1, padx=5, pady=2, sticky=tk.EW)
        manual_decrypt_frame.grid_columnconfigure(1, weight=1)
        ttk.Button(manual_decrypt_frame, text="Jalankan Dekripsi Manual", command=self.run_manual_decryption).grid(row=3, column=0, columnspan=2, pady=10)

    def reset_log_and_status(self):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.modern_status.config(text="Status: Menunggu", foreground="black")
        self.quantum_status.config(text="Status: Menunggu", foreground="black")
        self.qber_label.config(text="QBER: -")
        self.skr_label.config(text="SKR: -")
        
    def log_result(self, message):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.config(state=tk.DISABLED)
        self.results_text.see(tk.END)

    def run_modern_encryption(self):
        self.reset_log_and_status()
        self.log_result("Memulai Enkripsi Modern")
        plaintext = self.msg_input.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showerror("Error", "Pesan tidak boleh kosong.")
            return
        key = get_random_bytes(16)
        ciphertext, iv = encrypt_aes(key, plaintext)
        self.log_result(f"Kunci (hex): {key.hex()}")
        self.log_result(f"IV (hex): {iv.hex()}") #initialization vector
        self.log_result(f"Ciphertext (hex): {ciphertext.hex()}")
        if self.eve_present_var.get():
            self.modern_status.config(text="Status: Penyadapan Aktif TAPI TIDAK TERDETEKSI.", foreground="red")
            self.log_result("\nAnalisis: Eve diasumsikan berhasil mendapatkan kunci.")
        else:
            self.modern_status.config(text="Status: Enkripsi Berhasil.", foreground="green")
            self.log_result("\nAnalisis: Komunikasi aman selama kunci tidak bocor.")

    def run_quantum_encryption(self):
        self.reset_log_and_status()
        plaintext = self.msg_input.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showerror("Error", "Pesan tidak boleh kosong.")
            return
        self.log_result("Memulai Distribusi Kunci Kuantum (QKD)")
        self.quantum_status.config(text="Status: Menjalankan simulasi BB84", foreground="blue")
        self.qber_label.config(text="QBER: Menghitung")
        self.skr_label.config(text="SKR: Menghitung")
        threading.Thread(target=self._qkd_thread_task, args=(plaintext,), daemon=True).start()

    def _qkd_thread_task(self, plaintext):
        is_eve_active = self.eve_present_var.get()
        NOISE = 0.015 #noise 1.5%
        qkd_results = bb84_simulation(
            num_bits=500, 
            eve_present=is_eve_active,
            noise_level=NOISE
        )
        self.after(0, self._on_qkd_complete, qkd_results, plaintext)

    def _on_qkd_complete(self, results, plaintext):
        qber = results['qber']
        self.qber_label.config(text=f"QBER: {qber:.2%}")
        skr = calculate_skr(qber)
        self.skr_label.config(text=f"Secure Key Rate (SKR): {skr:.2%}")
        self.log_result(f"Estimasi Secure Key Rate (R): {skr:.2%}")

        DETECTION_THRESHOLD = 0.11 #sesuai teori, di atas 11% SKR menjadi 0
        if qber > DETECTION_THRESHOLD:
            self.quantum_status.config(text="Status: PENYADAP TERDETEKSI! ENKRIPSI DIBATALKAN.", foreground="red")
            self.log_result(f"Hasil QBER: {qber:.2%}. Melebihi batas aman ({DETECTION_THRESHOLD:.0%})!")
            self.log_result(f"SKR Negatif atau Nol: Tidak ada kunci aman yang bisa diekstrak.")
            self.log_result("\nAnalisis: Pesan tetap aman karena enkripsi dibatalkan.")
            return

        self.log_result(f"Hasil QBER: {qber:.2%}. Di bawah batas aman.")
        key = derive_aes_key(results['sifted_key'])
        
        if not key:
            self.quantum_status.config(text="Status: Gagal, kunci QKD terlalu pendek.", foreground="red")
            self.log_result("\nError: Kunci saringan tidak cukup. Coba lagi atau tambah jumlah bit.")
            return

        ciphertext, iv = encrypt_aes(key, plaintext)
        self.quantum_status.config(text="Status: Enkripsi dengan Kunci Kuantum Berhasil.", foreground="green")
        self.log_result(f"Kunci (dari QKD): {key.hex()}")
        self.log_result(f"IV (hex): {iv.hex()}")
        self.log_result(f"Ciphertext (hex): {ciphertext.hex()}")
        self.log_result("\nAnalisis: Kunci berhasil dibuat dan didistribusikan dengan aman.")

    def run_manual_decryption(self):
        key_hex = self.manual_key_entry.get().strip()
        iv_hex = self.manual_iv_entry.get().strip()
        ciphertext_hex = self.manual_ciphertext_entry.get().strip()

        if not (key_hex and iv_hex and ciphertext_hex):
            messagebox.showerror("Input Kosong", "Semua kolom (Kunci, IV, Ciphertext) harus diisi.")
            return
        try:
            key = bytes.fromhex(key_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted_text = decrypt_aes(key, iv, ciphertext)
            messagebox.showinfo("Hasil Dekripsi Manual", f"Pesan Asli Berhasil Didekripsi:\n\n'{decrypted_text}'")
        except ValueError:
            messagebox.showerror("Error Input", "Format Hex tidak valid. Pastikan hanya berisi karakter 0-9 dan a-f.")
        except Exception as e:
            messagebox.showerror("Error Dekripsi", f"Gagal mendekripsi: {e}")

if __name__ == "__main__":
    app = QKDvsModernApp()
    app.mainloop()
    #run_performance_test()