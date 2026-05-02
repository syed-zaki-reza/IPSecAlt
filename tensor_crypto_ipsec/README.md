# Tensor-Based Post-Quantum Cryptography System

## 🎯 Project Overview

A quantum-resistant cryptographic protocol as an alternative to IPsec, leveraging:
- **High-dimensional tensor mathematics** for unpredictable data transformations
- **AI-generated cryptographic logic** for dynamic, session-specific operations  
- **Chaotic mappings** (Logistic Map) for efficient, quantum-resistant encryption

## 🔐 Core Innovation

**Decoupled Cryptographic Orchestration** using chaotic tensor mappings:

```
C = (M ⊛ K) ⊕ A_AI
```

Where:
- `M` = Message tensor (3D grid, 8×8×8 = 512 bytes)
- `⊛` = Chaotic mapping (coordinate permutation via Logistic Map)
- `K` = Key tensor (generated from Logistic Map: x_{n+1} = μ·x_n·(1-x_n))
- `⊕` = XOR operation (1 CPU cycle)
- `A_AI` = AI-generated noise tensor

## 📁 Installation

```bash
cd tensor_crypto_ipsec
pip install -r requirements.txt
```

## 🚀 Quick Start

### Basic Encryption/Decryption

```python
from src import ChaosEngine, TensorEngine, AIConductor

# Initialize components
chaos = ChaosEngine(mu=4.0, x0=0.5)
tensor_engine = TensorEngine(chaos_engine=chaos)
conductor = AIConductor()

# Create session
session = conductor.initiate_session(
    session_id="demo_session",
    device_fingerprint="device_A",
    peer_fingerprint="device_B"
)

# Encrypt
message = b"Hello, Quantum-Safe World!"
encrypted = tensor_engine.encrypt(
    message, 
    session.mu, 
    session.x0, 
    session.session_id
)

print(f"Ciphertext size: {len(encrypted.ciphertext)} bytes")
print(f"Entropy score: {encrypted.entropy_score:.2f} bits")

# Decrypt
decrypted = tensor_engine.decrypt(
    encrypted.ciphertext,
    session.mu,
    session.x0,
    session.session_id
)

print(f"Original: {message}")
print(f"Decrypted: {decrypted.plaintext}")
assert message == decrypted.plaintext
```

### Router Simulation

```python
from src import RouterInterface, TensorEngine, ChaosEngine

# Create two router interfaces
router_a = RouterInterface("router_A", mode="simulation")
router_b = RouterInterface("router_B", mode="simulation")

# Set up crypto callbacks
chaos = ChaosEngine()
tensor = TensorEngine(chaos_engine=chaos)

def encrypt_cb(data, mu, x0, sid):
    return tensor.encrypt(data, mu, x0, sid)

def decrypt_cb(data, mu, x0, sid):
    return tensor.decrypt(data, mu, x0, sid)

router_a.set_crypto_callbacks(encrypt_cb, decrypt_cb)
router_b.set_crypto_callbacks(encrypt_cb, decrypt_cb)

# Initiate handshake
session_id = "sim_session_001"
router_a.initiate_handshake("router_B", session_id)

# Get handshake packet and respond
packets = router_a.get_simulated_packets(session_id)
response = router_b.respond_to_handshake(packets[0])

# Send encrypted data
original_data = b"Secret network message"
packet = router_a.send_encrypted_data(session_id, original_data)

# Receive and decrypt at router B
received_packets = router_a.get_simulated_packets(session_id)
decrypted = router_b.receive_data(received_packets[0])

print(f"Sent: {original_data}")
print(f"Received: {decrypted}")
```

## 🧪 Running Tests

```bash
# Run unit tests
python -m pytest tests/test_core.py -v

# Or with unittest
python -m unittest discover tests/ -v
```

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
├─────────────────────────────────────────────────────────┤
│  Router Interface  │  Packet Handling │ Session States  │
├─────────────────────────────────────────────────────────┤
│   Tensor Engine    │  Chaos Mapping   │  AI Conductor  │
│  (Encrypt/Decrypt) │ (Logistic Map)   │ (Session Mgmt) │
├─────────────────────────────────────────────────────────┤
│   Key Manager      │  Dictionary Mgr  │    Utilities   │
│   (HKDF/Rotate)    │ (Provisioning)   │ (Entropy/FPR)  │
└─────────────────────────────────────────────────────────┘
```

## 🔬 Key Features

### 1. Chaotic Tensor Mappings
- Uses Logistic Map: `x_{n+1} = μ·x_n·(1-x_n)` with μ ∈ [3.57, 4.0]
- Deterministic recreation via Mirror Chaos Engine
- No matrix multiplication - only XOR and memory addressing

### 2. AI Conductor
- Hybrid approach: pre-computed strategy tables + session adaptation
- Environmental entropy collection (cross-platform)
- 15-minute session TTL with automatic rotation

### 3. Linked Tensor Blocks
- Messages chunked into 512-byte blocks (8×8×8 tensors)
- 16-byte header metadata for padding recovery
- Supports arbitrary message sizes

### 4. Forward Secrecy
- Automatic key rotation (time-based and usage-based)
- HKDF-based hierarchical key derivation
- AES-encrypted key storage

## 📈 Performance Characteristics

| Operation | Complexity | Notes |
|-----------|------------|-------|
| XOR Layer | O(n) | 1 CPU cycle per byte |
| Permutation | O(n) | Memory addressing only |
| Key Generation | O(n) | Logistic map iterations |
| Total Encrypt | O(n) | Linear in message size |

## 🔒 Security Properties

1. **Quantum Resistance**: No reliance on integer factorization or discrete logarithms
2. **High-Dimensional Search Space**: 512-dimensional tensor permutation
3. **Chaotic Unpredictability**: Sensitive dependence on initial conditions
4. **Forward Secrecy**: Automatic key rotation prevents retrospective decryption

## 📝 License

MIT License - See LICENSE file for details.

## 🎓 Research Status

This is a **research prototype** for IEEE publication. Not suitable for production use without formal security analysis.
