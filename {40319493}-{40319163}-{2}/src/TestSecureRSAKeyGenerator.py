import unittest
import sys
import os
sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', 'src')))
from rsa_key_generator import SecureRSAKeyGenerator


class TestSecureRSAKeyGenerator(unittest.TestCase):
    def setUp(self):
        self.rsa = SecureRSAKeyGenerator(bits=2048)

    def test_miller_rabin_basic_cases(self):
        self.assertTrue(self.rsa.miller_rabin_test(2))
        self.assertTrue(self.rsa.miller_rabin_test(3))
        self.assertTrue(self.rsa.miller_rabin_test(5))
        self.assertTrue(self.rsa.miller_rabin_test(7))
        self.assertTrue(self.rsa.miller_rabin_test(11))
        self.assertFalse(self.rsa.miller_rabin_test(4))
        self.assertFalse(self.rsa.miller_rabin_test(6))
        self.assertFalse(self.rsa.miller_rabin_test(8))
        self.assertFalse(self.rsa.miller_rabin_test(9))
        self.assertFalse(self.rsa.miller_rabin_test(10))
        self.assertFalse(self.rsa.miller_rabin_test(0))
        self.assertFalse(self.rsa.miller_rabin_test(1))
        self.assertFalse(self.rsa.miller_rabin_test(-1))

    def test_miller_rabin_known_primes(self):
        known_primes = [97, 101, 103, 107, 109, 113, 127, 131, 137,
                        139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193]
        for prime in known_primes:
            self.assertTrue(self.rsa.miller_rabin_test(prime))

    def test_miller_rabin_known_composites(self):
        known_composites = [15, 21, 25, 27, 33, 35, 39, 49,
                            51, 55, 57, 65, 69, 77, 85, 87, 91, 93, 95, 99]
        for composite in known_composites:
            self.assertFalse(self.rsa.miller_rabin_test(composite))

    def test_prime_generation_properties(self):
        for bit_size in [1024, 2048]:
            generator = SecureRSAKeyGenerator(bits=bit_size)
            for _ in range(5):
                prime = generator.generate_prime()
                self.assertEqual(prime.bit_length(), bit_size // 2)
                self.assertEqual(prime % 2, 1)
                self.assertTrue(generator.miller_rabin_test(prime))

    def test_gcd_function(self):
        test_cases = [(48, 18, 6), (17, 13, 1), (100, 25, 25),
                      (7, 7, 7), (1071, 462, 21)]
        for a, b, expected in test_cases:
            self.assertEqual(self.rsa.gcd(a, b), expected)

    def test_mod_inverse_correctness(self):
        test_cases = [(3, 7), (7, 12), (17, 43)]
        for e, phi in test_cases:
            if self.rsa.gcd(e, phi) == 1:
                d = self.rsa.mod_inverse(e, phi)
                self.assertIsNotNone(d)
                self.assertEqual((e * d) % phi, 1)

    def test_mod_inverse_no_solution(self):
        test_cases = [(4, 6), (6, 9), (10, 15)]
        for e, phi in test_cases:
            self.assertIsNone(self.rsa.mod_inverse(e, phi))

    def test_key_generation_structure(self):
        keys = self.rsa.generate_secure_keys()
        self.assertIn('public_key', keys)
        self.assertIn('private_key', keys)
        self.assertIn('p', keys)
        self.assertIn('q', keys)
        self.assertIn('phi', keys)
        e, n = keys['public_key']
        d, n_private = keys['private_key']
        p, q, phi = keys['p'], keys['q'], keys['phi']
        self.assertEqual(n, n_private)
        self.assertEqual(n, p * q)
        self.assertEqual(phi, (p - 1) * (q - 1))
        self.assertEqual(e, 65537)
        self.assertEqual((e * d) % phi, 1)

    def test_key_security_properties(self):
        for _ in range(3):
            keys = self.rsa.generate_secure_keys()
            p, q = keys['p'], keys['q']
            n = keys['public_key'][1]
            self.assertNotEqual(p, q)
            self.assertTrue(self.rsa.miller_rabin_test(p))
            self.assertTrue(self.rsa.miller_rabin_test(q))
            self.assertEqual(p.bit_length(), self.rsa.bits // 2)
            self.assertEqual(q.bit_length(), self.rsa.bits // 2)
            self.assertGreaterEqual(n.bit_length(), self.rsa.bits - 1)
            self.assertLessEqual(n.bit_length(), self.rsa.bits)

    def test_encryption_decryption_basic(self):
        keys = self.rsa.generate_secure_keys()
        public_key = keys['public_key']
        private_key = keys['private_key']
        test_messages = ["Hello, World!", "RSA Encryption Test",
                         "12345", "Special chars: !@#$%^&*()", "سلام", ""]
        for message in test_messages:
            with self.subTest(message=message):
                ciphertext = self.rsa.secure_encrypt(message, public_key)
                decrypted = self.rsa.secure_decrypt(ciphertext, private_key)
                self.assertEqual(message, decrypted)
                if message:
                    message_as_int = int.from_bytes(
                        message.encode('utf-8'), "big")
                    self.assertNotEqual(ciphertext, message_as_int)

    def test_cross_key_decryption_failure(self):
        keys1 = self.rsa.generate_secure_keys()
        keys2 = self.rsa.generate_secure_keys()
        message = "Cross-key test"
        ciphertext = self.rsa.secure_encrypt(message, keys1['public_key'])
        try:
            wrong_decryption = self.rsa.secure_decrypt(
                ciphertext, keys2['private_key'])
            self.assertNotEqual(message, wrong_decryption)
        except (UnicodeDecodeError, ValueError, OverflowError):
            pass

    def test_bit_size_configurations(self):
        bit_sizes = [1024, 2048, 4096]
        for bits in bit_sizes:
            with self.subTest(bits=bits):
                generator = SecureRSAKeyGenerator(bits=bits)
                keys = generator.generate_secure_keys()
                n = keys['public_key'][1]
                self.assertGreaterEqual(n.bit_length(), bits - 1)
                self.assertLessEqual(n.bit_length(), bits)
                message = f"Test message for {bits} bits"
                ciphertext = generator.secure_encrypt(
                    message, keys['public_key'])
                decrypted = generator.secure_decrypt(
                    ciphertext, keys['private_key'])
                self.assertEqual(message, decrypted)

    def test_private_exponent_properties(self):
        keys = self.rsa.generate_secure_keys()
        d = keys['private_key'][0]
        e = keys['public_key'][0]
        phi = keys['phi']
        self.assertEqual((e * d) % phi, 1)
        self.assertGreater(d, 0)
        self.assertLess(d, phi)

    def test_unicode_message_handling(self):
        keys = self.rsa.generate_secure_keys()
        unicode_messages = ["English text", "113434144523",
                            "Español con eñe", "Emoji test: 🔐🔑💻🌍"]
        for message in unicode_messages:
            with self.subTest(message=message):
                ciphertext = self.rsa.secure_encrypt(
                    message, keys['public_key'])
                decrypted = self.rsa.secure_decrypt(
                    ciphertext, keys['private_key'])
                self.assertEqual(message, decrypted)


if __name__ == '__main__':
    unittest.main(verbosity=2)
