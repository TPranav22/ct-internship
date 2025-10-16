# My First Cybersecurity Toolkit: An Educational Project

**Author:** T Pranav
**Date:** October 16, 2025
**Course:** Cyber Security and Ethical Hacking

---

## ⚠️ Ethical Use and Legal Disclaimer

This toolkit is created for **strictly educational purposes** as part of a learning project in cybersecurity. The tools included are designed to demonstrate fundamental security concepts in a controlled and safe environment.

-   **DO NOT** use this toolkit on any computer, network, or system that you do not own or have explicit, written permission to test.
-   The default target for all network-related modules is `127.0.0.1` (localhost) to ensure all operations are safely contained on your own machine.
-   Unauthorized scanning or testing of systems can be illegal. The author is not responsible for any misuse or damage caused by this toolkit.

---

## 📖 Project Description

This project is a simple, modular toolkit built in Python to explore two fundamental concepts in cybersecurity: network reconnaissance and password security. It is intended to help beginners understand *how* basic security tools work and, more importantly, *how to defend* against the techniques they demonstrate.

The toolkit features a command-line menu to access its different modules.

---

## 🚀 How to Run the Toolkit

1.  **Prerequisites:** You need Python 3 installed on your system.
2.  **Navigate:** Open a terminal or command prompt and navigate to the project directory (`my_toolkit/`).
3.  **Execute:** Run the main script using the following command:
    ```bash
    python main.py
    ```
4.  **Interact:** A menu will appear. Enter the number corresponding to the module you wish to run.

---

## 🛠️ Modules Explained

This toolkit contains the following modules:

### 1. Port Scanner

* **What it does:** This module attempts to connect to a predefined list of common ports (e.g., 80 for HTTP, 443 for HTTPS) on `localhost`. It reports which of these ports are "open," indicating that a service is likely running and listening for connections.
* **Educational Purpose:** This demonstrates the first step of network reconnaissance, where an attacker identifies potential points of entry into a system.
* **🛡️ How to Defend Against Port Scanning:**
    * **Firewalls:** The primary defense. A well-configured firewall acts as a barrier, blocking all incoming connection attempts to ports that are not explicitly allowed.
    * **Intrusion Detection/Prevention Systems (IDS/IPS):** These systems can be configured to detect the patterns of a port scan (many connection attempts from a single source in a short time) and can automatically block the scanning IP address.
    * **Principle of Least Privilege:** Only keep ports open if they are absolutely necessary for a service to function. If a service is not needed, it should be disabled.

### 2. Common Password Checker

* **What it does:** This is a **defensive tool**. It prompts the user for a password and checks it against a small, included `wordlist.txt` file containing some of the most commonly used passwords. It reports whether the password is found on the list.
* **Educational Purpose:** This module demonstrates the weakness of using simple, common, or default passwords. It simulates the logic of a "dictionary attack" or "brute-force" attack, where an attacker tries a list of known passwords to gain access.
* **🛡️ How to Defend Against Weak Passwords:**
    * **Strong Password Policies:** Enforce requirements for password length (e.g., 12+ characters), complexity (uppercase, lowercase, numbers, symbols), and history (preventing reuse of old passwords).
    * **Account Lockout Mechanisms:** After a set number of failed login attempts (e.g., 5), the account should be temporarily locked. This makes automated brute-force attacks impractically slow.
    * **Multi-Factor Authentication (MFA):** The most effective defense. Even if an attacker guesses the password, they still cannot log in without the second factor (e.g., a code from a mobile app or SMS).
    * **CAPTCHA:** Prevents automated scripts from attempting to log in by requiring a task that is easy for a human but difficult for a bot.

---