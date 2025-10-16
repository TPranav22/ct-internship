# password_checker.py

def check_password(password, wordlist_file):
    """
    Checks if a given password exists in a list of common passwords.
    This demonstrates the weakness of using common passwords.
    """
    print("\n[+] Checking password strength...")
    try:
        with open(wordlist_file, 'r') as file:
            # Read all lines and strip newline characters
            common_passwords = [line.strip() for line in file]

        if password in common_passwords:
            print(f"  [!] DANGER: '{password}' is a very common password and is not secure.")
        else:
            print(f"  [+] SUCCESS: '{password}' was not found in the common password list.")

    except FileNotFoundError:
        print(f"  [X] ERROR: The wordlist file '{wordlist_file}' was not found.")
    except Exception as e:
        print(f"  [X] An error occurred: {e}")