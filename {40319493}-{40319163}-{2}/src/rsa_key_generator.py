import random


class SecureRSAKeyGenerator:
    def __init__(self, bits=2048):
        self.bits = bits

    def miller_rabin_test(self, n, k=10):
        if n <= 1 or n % 2 == 0:
            return n == 2
        if n == 3:
            return True

        r, d = 0, n-1
        while (d % 2 == 0):
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_prime(self):
        while True:
            n = random.getrandbits(self.bits // 2)

            if n % 2 == 0:
                n += 1

            if n.bit_length() != self.bits // 2:
                continue

            if self.miller_rabin_test(n, k=20):
                return n

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(self, e, phi):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        gcd, x, _ = extended_gcd(e, phi)
        if gcd != 1:
            return None
        return (x % phi + phi) % phi

    def generate_secure_keys(self):

        p = self.generate_prime()
        q = self.generate_prime()

        while p == q:
            q = self.generate_prime()

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537

        d = self.mod_inverse(e, phi)

        return {
            'public_key': (e, n),
            'private_key': (d, n),
            'p': p,
            'q': q,
            'phi': phi
        }

    def secure_encrypt(self, message, public_key):
        e, n = public_key
        utf8_bytes = message.encode('utf-8')
        number = int.from_bytes(utf8_bytes, "big")

        return pow(number, e, n)

    def secure_decrypt(self, ciphertext, private_key):
        d, n = private_key
        message = pow(ciphertext, d, n)

        byte_length = (message.bit_length() + 7) // 8
        message_bytes = message.to_bytes(byte_length, "big")

        return message_bytes.decode('utf-8')
