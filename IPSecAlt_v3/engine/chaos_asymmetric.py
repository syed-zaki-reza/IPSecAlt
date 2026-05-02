import math
import secrets
from typing import Tuple

class ChebyshevKeyExchange:
    """
    Implements Asymmetric Key Exchange using Chaotic Chebyshev Maps.
    
    Research Context:
    Standard Diffie-Hellman relies on Discrete Logarithms ($g^a mod p$).
    This module relies on the 'Chaotic Semigroup Property' of Chebyshev Polynomials:
    T_r(T_s(x)) = T_{rs}(x) = T_s(T_r(x))
    
    This provides a 'Trapdoor' that is computationally efficient but 
    mathematically hard to reverse without the exponent (r or s).
    """

    def __init__(self):
        # The map is defined on [-1, 1]. 
        # We need high precision, but for prototype Python floats are sufficient.
        pass

    def _chebyshev_map(self, x: float, n: int) -> float:
        """
        Computes the N-th Chebyshev polynomial T_n(x).
        
        Recursive Def: T_n(x) = 2x * T_{n-1}(x) - T_{n-2}(x)
        Trigonometric Def: T_n(x) = cos(n * arccos(x))
        
        We use the Trig definition for O(1) speed, provided x is in [-1, 1].
        """
        # Clamp x to [-1, 1] to avoid domain errors in acos
        x = max(min(x, 1.0), -1.0)
        
        # The "Cheap" Asymmetric Equation
        return math.cos(n * math.acos(x))

    def generate_keypair(self, global_seed: float) -> Tuple[int, float]:
        """
        Generates a Private/Public key pair based on a Global Seed (x).
        
        Args:
            global_seed (float): A public random number agreed upon by the network.
            
        Returns:
            private_key (int): A large secret integer.
            public_key (float): The result of the map T_priv(seed).
        """
        # 1. Generate Private Key (Large random integer)
        # In real crypto, this should be 2048+ bits. 
        # For prototype, we use 16 bits for speed/readability.
        private_key = secrets.randbelow(50000) + 10000 
        
        # 2. Calculate Public Key
        # A = T_s(x)
        public_key = self._chebyshev_map(global_seed, private_key)
        
        return private_key, public_key

    def derive_shared_secret(self, peer_public_key: float, my_private_key: int) -> float:
        """
        Derives the shared secret using the peer's Public Key and my Private Key.
        
        Math:
        Secret = T_myPriv(PeerPub) 
               = T_myPriv(T_peerPriv(x)) 
               = T_{myPriv * peerPriv}(x)
        """
        # K = T_r(A)
        secret = self._chebyshev_map(peer_public_key, my_private_key)
        
        # The result is in [-1, 1]. 
        # We normalize it to [0, 1] for the Logistic Map engine.
        normalized_secret = (secret + 1.0) / 2.0
        return normalized_secret

# --- Unit Test / Demonstration ---
if __name__ == "__main__":
    print("[TEST] Initializing Chebyshev Key Exchange...")
    
    cke = ChebyshevKeyExchange()
    
    # 1. Public Setup (The Network agrees on a seed x)
    global_seed = 0.3579 # Arbitrary public number
    print(f"[SETUP] Global Seed x: {global_seed}")
    
    # 2. Alice generates keys
    alice_priv, alice_pub = cke.generate_keypair(global_seed)
    print(f"[ALICE] Priv: {alice_priv}, Pub: {alice_pub:.6f}")
    
    # 3. Bob generates keys
    bob_priv, bob_pub = cke.generate_keypair(global_seed)
    print(f"[BOB]   Priv: {bob_priv}, Pub: {bob_pub:.6f}")
    
    # 4. Exchange & Derive
    # Alice takes Bob's Pub, Bob takes Alice's Pub
    alice_secret = cke.derive_shared_secret(bob_pub, alice_priv)
    bob_secret = cke.derive_shared_secret(alice_pub, bob_priv)
    
    print(f"\n[RESULT] Alice's Secret: {alice_secret:.10f}")
    print(f"[RESULT] Bob's Secret:   {bob_secret:.10f}")
    
    # 5. Validation
    # Floating point math has tiny errors, so we check "Close Enough"
    match = math.isclose(alice_secret, bob_secret, rel_tol=1e-9)
    print(f"[VALIDATION] Secrets Match? {match}")
    
    assert match
    print("[SUCCESS] Asymmetric Chaos Exchange successful.")