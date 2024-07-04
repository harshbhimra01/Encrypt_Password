from cryptography.fernet import Fernet


def write_key():
    """Generate and write a new key to key.key file."""
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)
    print("Key generated and saved to key.key.")


def load_key():
    """Load the key from key.key file."""
    try:
        with open('key.key', 'rb') as key_file:
            key = key_file.read()
        print("Key loaded successfully.")
        return key
    except FileNotFoundError:
        print("Key file not found. Please generate a key first using 'write_key()' function.")
        return None


def view_passwords(fer):
    """View and decrypt passwords from Password.txt."""
    try:
        with open("Password.txt", 'r') as v:
            for line in v.readlines():
                data = line.strip()
                if '|' in data:
                    user, passw = data.split('|')
                    try:
                        decrypted_password = fer.decrypt(passw.encode()).decode()
                        print(f"User: {user}, Password: {decrypted_password}")
                    except Exception as e:
                        print(f"Error decrypting password for user {user}: {e}")
                else:
                    print("Improperly formatted line:", data)
    except FileNotFoundError:
        print("Password file not found. Please add a password first.")


def add_password(fer):
    """Add a new account name and encrypted password to Password.txt."""
    name = input("Account name: ")
    pwd = input("Password: ")

    with open("Password.txt", 'a') as a:
        encrypted_password = fer.encrypt(pwd.encode()).decode()
        a.write(f"{name}|{encrypted_password}\n")
    print("Password added successfully.")


def main():
    key = load_key()
    if key is None:
        return

    fer = Fernet(key)

    while True:
        mode = input(
            "Would you like to view existing passwords (view), add a new password (add), or quit (q)? ").lower()
        if mode == "view":
            view_passwords(fer)
        elif mode == "add":
            add_password(fer)
        elif mode == "q":
            break
        else:
            print("Enter a valid mode (view, add, q)!")


if __name__ == "__main__":
    main()
