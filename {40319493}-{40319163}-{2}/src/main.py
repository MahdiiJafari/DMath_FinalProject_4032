import sys
from rsa_key_generator import SecureRSAKeyGenerator


def display_menu():
    print("\nRSA Encryption/Decryption Menu")
    print("1. Generate RSA Keys")
    print("2. Encrypt Message")
    print("3. Decrypt Message")
    print("4. Exit")
    return input("Select an option (1-4): ")


def main():
    rsa = SecureRSAKeyGenerator(bits=2048)
    keys = None
    public_key = None
    private_key = None

    while True:
        choice = display_menu()

        if choice == '1':
            print("\nGenerating RSA keys...")
            keys = rsa.generate_secure_keys()
            public_key = keys['public_key']
            private_key = keys['private_key']
            print(f"Public Key: {public_key}")
            print(f"Private Key: {private_key}")
            print("Keys generated successfully!")

        elif choice == '2':
            if not keys:
                print("\nError: Please generate keys first!")
                continue
            try:
                message = input("\nEnter message to encrypt: ")
                ciphertext = rsa.secure_encrypt(message, public_key)
                print(f"Encrypted message (ciphertext): {ciphertext}")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '3':
            if not keys:
                print("\nError: Please generate keys first!")
                continue
            try:
                ciphertext = int(input("\nEnter ciphertext to decrypt: "))
                decrypted_message = rsa.secure_decrypt(ciphertext, private_key)
                print(f"Decrypted message: {decrypted_message}")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '4':
            print("\nExiting program...")
            sys.exit(0)

        else:
            print("\nInvalid option! Please select 1-4.")


if __name__ == "__main__":
    main()
