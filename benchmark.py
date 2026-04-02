import os
import subprocess
import time
import sys

sys.stdout = open(os.devnull, 'w')
try:
    from client import run_client as pake_run_client
    from tls_client import run_client as tls_run_client
finally:
    sys.stdout.close()
    sys.stdout = sys.__stdout__

def generate_certs():
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("Generating self-signed cert for TLS testing...")
        try:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", "key.pem", "-out", "cert.pem",
                "-days", "365", "-nodes", "-subj", "/CN=localhost"
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("Certificates generated.")
        except Exception as e:
            print(f"Failed to generate certs. Ensure openssl is installed. {e}")
            print("Run 'sudo apt install openssl' if in WSL/Ubuntu.")
            sys.exit(1)

def run_benchmarks(iterations=5):
   
    print("Starting SPAKE2+ and TLS servers in the background...")
    server_cmd = [sys.executable, "server.py"]
    tls_server_cmd = [sys.executable, "tls_server.py"]
    
    server_proc = subprocess.Popen(server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls_server_proc = subprocess.Popen(tls_server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(2)
    
    try:
        print(f"\n--- Running SPAKE2+ Benchmark ({iterations} iterations) ---")
        pake_times = []
        for i in range(iterations):
            
            with open(os.devnull, 'w') as devnull:
                stdout_bak = sys.stdout
                sys.stdout = devnull
            
                t_dict = pake_run_client("alice", "password123")
                sys.stdout = stdout_bak
                
            if t_dict is not None:
                pake_times.append(t_dict)
            else:
                print(f"Iteration {i+1} failed.")
            time.sleep(0.1) 
            
        print(f"--- Running TLS Benchmark ({iterations} iterations) ---")
        tls_times = []
        for i in range(iterations):
            try:
                with open(os.devnull, 'w') as devnull:
                    stdout_bak = sys.stdout
                    sys.stdout = devnull
                    t_dict = tls_run_client("password123")
                    sys.stdout = stdout_bak
                if t_dict is not None:
                    tls_times.append(t_dict)
            except Exception as e:
                print(f"TLS Client Error on iteration {i+1}: {e}")
            time.sleep(0.1)
            
        print("\n================== RESULTS ==================")
        if pake_times:
            print("\n [SPAKE2+ Summary - Average Times]:")
            keys = pake_times[0].keys()
            for key in keys:
                avg = sum(d[key] for d in pake_times) / len(pake_times)
                print(f"    - {key}: {avg:.2f} ms")
        else:
            print("\n [SPAKE2+ Summary]: Failed to collect data")
            
        if tls_times:
            print("\n [TLS 1.3 Summary - Average Times]:")
            keys = tls_times[0].keys()
            for key in keys:
                avg = sum(d[key] for d in tls_times) / len(tls_times)
                print(f"    - {key}: {avg:.2f} ms")
        else:
            print("\n [TLS 1.3 Summary]: Failed to collect data")
        print("\n=============================================\n")

    finally:
        print("Shutting down servers...")
        server_proc.terminate()
        tls_server_proc.terminate()
        server_proc.wait()
        tls_server_proc.wait()

if __name__ == "__main__":
    generate_certs()
    run_benchmarks(10)
