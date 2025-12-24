import time
import os
import secrets
import random

# Data dummy
def generate_dummy_data(size_in_kb):
    bytes_size = int(size_in_kb * 1024)
    return secrets.token_bytes(bytes_size)

def mock_quantum_encryption(data):
    file_size = len(data)
    
    #base Overhead (Latency Awal)
    initialization_overhead = 0.001  #20ms fixed time
    
    #variabilitas CPU (Jitter)
    cpu_variance = random.uniform(0.95, 1.05) 
    
    #base Rate (Kecepatan murni per byte)
    base_rate_per_byte = 0.0000001
    
    #rumus Waktu: (Overhead + (Ukuran * Rate)) * Variasi CPU
    process_time = (initialization_overhead + (file_size * base_rate_per_byte)) * cpu_variance
    
    time.sleep(process_time) 
    return data 

def calculate_throughput(file_size_kb):
    print(f"Memulai Pengujian untuk Ukuran Data : {file_size_kb} KB")

    #plaintext (Tp)
    plaintext = generate_dummy_data(file_size_kb)
    
    #mulai Pengukuran Waktu (Gunakan perf_counter untuk presisi tinggi)
    start_time = time.perf_counter()
    
    #eksekusi enkripsi
    encrypted_data = mock_quantum_encryption(plaintext)
    
    end_time = time.perf_counter()
    
    #hitung ET (Encryption Time)
    encryption_time = end_time - start_time
    
    #hitung throughput
    #rumus Throughput = Tp / Et
    if encryption_time > 0:
        throughput_kbps = file_size_kb / encryption_time
        throughput_mbps = throughput_kbps / 1024 #konversi ke MB/s
    else:
        throughput_kbps = 0
        throughput_mbps = 0

    # Output
    print(f"Total Plaintext (Tp) : {file_size_kb} KB")
    print(f"Encryption Time (Et) : {encryption_time:.6f} detik")
    print(f"Throughput           : {throughput_kbps:.2f} KB/s")
    print(f"Throughput (MB/s)    : {throughput_mbps:.2f} MB/s")
    print("-" * 50)
    
    return throughput_mbps

if __name__ == "__main__":
    #skenario pengujian data (1MB, 5MB, 10MB)
    test_sizes_kb = [1024, 5120, 10240] 
    
    results = {}
    
    print("MENGUJI THROUGHPUT")
    
    for size in test_sizes_kb:
        mb_rate = calculate_throughput(size)
        results[size] = mb_rate

    avg_throughput = sum(results.values()) / len(results)
    print(f"\nRata-rata Throughput: {avg_throughput:.2f} MB/s")