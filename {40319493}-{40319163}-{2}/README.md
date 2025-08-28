# RSA Encryption

---

## TEAM :

### Mahdi Jafari (40319493)

### Amir Hossein Taji (40319163)

---

## RSA Algorithm Steps

RSA is a cryptography system that relies on the difficulty of factoring large numbers to secure data. 

1. **Choose Two Prime Numbers (p, q)**:
    
    - Select two large prime numbers, `p` and `q`. In the script, the `generate_prime` method uses the Miller-Rabin primality test to generate these primes.
            
2. **Compute n**:
    
    - Calculate `n = p × q`. This modulus is used in both public and private keys.
        
    - In the script, `n = p * q` is computed in `generate_secure_keys`.
        
    - `n` determines the maximum message size that can be encrypted (messages must be smaller than `n`).
        
3. **Compute Euler’s Totient Function φ(n)**:
    
    - Calculate `φ(n) = (p - 1) × (q - 1)`, the number of integers coprime to `n`.
        
    - In the script, `phi = (p - 1) * (q - 1)` is computed in `generate_secure_keys`.
        
    - `φ(n)` is used to select the public exponent `e` and compute the private exponent `d`.
        
4. **Choose e**:
    
    - Select a public exponent `e` such that `1 < e < φ(n)` and `gcd(e, φ(n)) = 1`.
        
    - The script uses `e = 65537`.
        
    - The GCD is computed using the `gcd` method to ensure coprimality (usualy e = 65537).
        
5. **Compute d**:
    
    - Find the private exponent `d` such that `d · e ≡ 1 (mod φ(n))`, meaning `d` is the modular inverse of `e` modulo `φ(n)`.
        
    - The script uses the `mod_inverse` method, which employs the Extended Euclidean Algorithm to compute `d`.
        
6. **Keys**:
    
    - **Public Key**: `(e, n)` — used for encryption, shareable with anyone.
        
    - **Private Key**: `(d, n)` — used for decryption, kept secret.
        
7. **Encryption**:
    
    - To encrypt a message `m`, compute `c = m^e mod n`, where `c` is the ciphertext.
        
    - In the script, `secure_encrypt` converts the message to a number (via UTF-8 encoding), checks if it’s smaller than `n`, and computes `pow(number, e, n)`.
                
8. **Decryption**:
    
    - To decrypt the ciphertext `c`, compute `m = c^d mod n`.
        
    - In the script, `secure_decrypt` computes `pow(ciphertext, d, n)`, converts the result to bytes, and decodes it to a string.

## Miller-Rabin Primality Test
The Miller-Rabin test is a algorithm to determine if a number is prime, used in the script’s `miller_rabin_test` method to generate primes `p` and `q`.

### How It Works

- **Input**: A number `n` and a parameter `k` (iterations, default 20).
    
- **Steps**:
    
    1. If `n ≤ 1` or `n` is even, return `False` (except `n = 2`, which is prime). If `n = 3`, return True.
        
    2. Write `n - 1` as `2^r × d`, where `d` is odd.
        
    3. For `k` iterations:
        
        - Choose a random base `a` (where `2 ≤ a < n - 1`).
            
        - Compute` x = a^d mod n`. If `x = 1` or `x = n - 1`, continue to the next iteration.
            
        - For `r - 1` times, compute `x = x^2 mod n`. If `x = n - 1`, continue; otherwise, if no condition is met, `n` is composite.
            
    4. If all iterations pass, `n` is likely prime (`error probability < 4^(-k)`).
        
- **In the Script**: `generate_prime` uses Miller-Rabin to test random numbers until a prime is found.

## Euclidean Algorithm (GCD)
- For numbers `a` and `b`, compute `a` mod `b`, then replace `a` with `b` and `b` with `a` mod `b`.
    
- Continue until `b = 0`; then `a` is the GCD.

## Extended Euclidean Algorithm

The Extended Euclidean Algorithm finds integers `x` and `y` such that `ax + by = gcd(a, b)`. In RSA, it computes `d`, the modular inverse of `e` modulo `φ(n)`.

### How It Works

- **Input**: Numbers `a` and `b`.
    
- **Output**: `gcd(a, b)` and coefficients `x`, `y` satisfying `ax + by = gcd(a, b)`.
    
- **Steps**:
    
    1. Initialize `x = 0`, `y = 1`, `last_x = 1`, `last_y = 0`.
        
    2. While `b ≠ 0`:
        
        - Compute quotient `q = a // b` and remainder `r = a % b`.
            
        - Update `a` = `b`, `b = r`.
            
        - Update `x` and `y`: `temp = x`, `x = last_x - q * x`, `last_x = temp` (similarly for y).
            
    3. When `b = 0`, `a` is the GCD, and `last_x`, `last_y` are the coefficients.

