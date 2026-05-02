import time
import sys
import os

# Adjust path to allow imports from parent directory
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from network.router_node import RouterNode, ConnectionState

def run_hybrid_simulation():
    print("============================================================")
    print("   LCTC: Lightweight Chaotic Tensor Cryptography (v3)       ")
    print("   IEEE Research Prototype - Hybrid Asymmetric/Symmetric    ")
    print("============================================================\n")

    # 1. Initialize Network Nodes
    print("[1] Initializing Nodes...")
    alice = RouterNode("ROUTER_ALICE")
    bob = RouterNode("ROUTER_BOB")
    
    # 2. Start Handshake (Asymmetric Phase)
    print("\n[2] Starting Post-Quantum Handshake (Chebyshev Map)...")
    start_hs = time.perf_counter()
    
    # Alice -> Bob: "Here is my Public Key"
    msg_1 = alice.initiate_handshake()
    
    # Bob processes Alice's Key -> Derives Secret -> Sends his Key
    response = bob.process_incoming_packet(msg_1)
    
    # Alice processes Bob's Key -> Derives Secret
    if response:
        alice.process_incoming_packet(response)
        
    end_hs = time.perf_counter()
    
    # 3. Verify Security Association
    print("\n[3] Verifying Security Association...")
    print(f"    Alice State: {alice.state}")
    print(f"    Bob State:   {bob.state}")
    
    if alice.shared_secret == bob.shared_secret:
        print(f"    [SUCCESS] Shared Secrets Match: {alice.shared_secret:.10f}")
        print(f"    [PERF] Handshake Latency: {(end_hs - start_hs)*1000:.4f} ms")
    else:
        print(f"    [FAIL] Mismatch! A: {alice.shared_secret} != B: {bob.shared_secret}")
        return

    # 4. Secure Data Transmission (Symmetric Phase)
    print("\n[4] Starting High-Speed Data Session (Logistic Map)...")
    message = "Standard cryptographic algorithms like RSA are vulnerable to Shor's Algorithm."
    print(f"    Original Message: '{message}'")
    
    start_tx = time.perf_counter()
    
    # Encrypt & Send
    encrypted_packet = alice.send_data(message)
    print(f"    [WIRE] Transmitted {len(encrypted_packet)} bytes of encrypted tensor data.")
    
    # Receive & Decrypt
    decrypted_text = bob.process_incoming_packet(encrypted_packet)
    
    end_tx = time.perf_counter()
    
    # 5. Final Validation
    print("\n[5] Validation Results")
    if decrypted_text == message:
        print("    [SUCCESS] Decryption Integrity Verified.")
        print(f"    [PERF] Encryption/Decryption Latency: {(end_tx - start_tx)*1000:.4f} ms")
    else:
        print(f"    [FAIL] Content mismatch: '{decrypted_text}'")

    print("\n============================================================")
    print("   PROTOTYPE SIMULATION COMPLETE")
    print("============================================================")

if __name__ == "__main__":
    run_hybrid_simulation()