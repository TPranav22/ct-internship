# scanner.py

import socket

def scan_ports(host, ports):
    """
    Scans a list of specified ports on a given host to see if they are open.
    For educational purposes, this is designed to be slow and simple.
    """
    print(f"\n[+] Starting port scan on {host}...")
    for port in ports:
        try:
            # Create a new socket object
            # AF_INET specifies IPv4, SOCK_STREAM specifies TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a timeout to avoid waiting too long for a response
            socket.setdefaulttimeout(0.5)

            # connect_ex returns 0 if the connection is successful (port is open)
            result = s.connect_ex((host, port))

            if result == 0:
                print(f"  [!] Port {port} is OPEN")
            # You can add an else statement here to show closed ports if you want
            # else:
            #     print(f"  Port {port} is closed")

            s.close()

        except socket.error as e:
            print(f"Couldn't connect to server: {e}")
    print("[+] Port scan complete.")