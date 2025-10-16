# main.py

# Import the functions from your other modules
from scanner import scan_ports
from password_checker import check_password

def display_menu():
    """Displays the main menu to the user."""
    print("\n--- Cybersecurity Toolkit for Education ---")
    print("1. Port Scanner (on localhost)")
    print("2. Common Password Checker")
    print("99. Exit")
    return input("Choose an option: ")

def main():
    """Main function to run the toolkit."""
    while True:
        choice = display_menu()
        if choice == '1':
            # Run the Port Scanner module
            target_host = '127.0.0.1' # Always use localhost for safety
            print(f"Scanning target: {target_host}")
            # Define a small, common range of ports to check for the project
            ports_to_scan = [22, 80, 443, 8080]
            scan_ports(target_host, ports_to_scan)

        elif choice == '2':
            # Run the Password Checker module
            password = input("Enter a password to check against the common list: ")
            wordlist_file = 'wordlist.txt'
            check_password(password, wordlist_file)

        elif choice == '99':
            print("Exiting toolkit. Stay safe!")
            break
        else:
            print("Invalid option, please try again.")

if __name__ == "__main__":
    main()