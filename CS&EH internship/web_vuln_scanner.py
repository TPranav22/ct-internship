import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin, urlparse
import sys

# --- Vulnerability Specific Payloads and Checks ---

# Payloads for testing Cross-Site Scripting (XSS)
XSS_PAYLOADS = [
    "<script>alert('xss-test')</script>",
    "<img src=x onerror=alert('xss-test')>",
    "'\"><script>alert('xss-test')</script>"
]

# Error signatures for error-based SQL Injection (SQLi)
SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax;",
    "warning: mysql_fetch_array()",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated"
]

# Payloads for testing SQL Injection
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin'--",
    "admin' #"
]

class WebVulnerabilityScanner:
    """
    A basic web vulnerability scanner to detect common web application vulnerabilities.
    """
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        self.discovered_links = set()

    def crawl(self, url=None):
        """
        Recursively crawls a website to discover all unique internal links.

        Args:
            url (str, optional): The URL to start crawling from. Defaults to the base URL.
        """
        if url is None:
            url = self.base_url
        
        href = str(url)
        if href in self.discovered_links or self.domain_name not in urlparse(href).netloc:
            return

        print(f"[*] Crawling: {href}")
        self.discovered_links.add(href)

        try:
            response = self.session.get(href, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all anchor tags
            for a_tag in soup.find_all('a', href=True):
                link = urljoin(self.base_url, a_tag['href'])
                # Recurse if the link is within the same domain
                self.crawl(link)
        except requests.RequestException as e:
            print(f"[-] Could not request {href}: {e}")
            return
    
    def get_forms(self, url):
        """
        Extracts all HTML form details from a given URL.

        Args:
            url (str): The URL to extract forms from.

        Returns:
            list: A list of BeautifulSoup form objects.
        """
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except requests.RequestException as e:
            print(f"[-] Could not fetch forms from {url}: {e}")
            return []

    def submit_form(self, form, url, value):
        """
        Submits a form with a given value in all its input fields.

        Args:
            form (bs4.element.Tag): The BeautifulSoup form object.
            url (str): The URL where the form is located.
            value (str): The payload/value to submit.

        Returns:
            requests.Response: The HTTP response after form submission.
        """
        action = form.get('action')
        post_url = urljoin(url, action)
        method = form.get('method', 'get').lower()

        inputs_list = form.find_all(['input', 'textarea'])
        post_data = {}
        for input_tag in inputs_list:
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            if input_type == 'text':
                post_data[input_name] = value
            # You can extend this to handle other input types
        
        try:
            if method == 'post':
                return self.session.post(post_url, data=post_data, timeout=5)
            else:
                return self.session.get(post_url, params=post_data, timeout=5)
        except requests.RequestException as e:
            print(f"[-] Error submitting form to {post_url}: {e}")
            return None

    def scan_xss(self, url):
        """
        Scans a URL for Cross-Site Scripting (XSS) vulnerabilities.
        """
        forms = self.get_forms(url)
        print(f"\n[*] Scanning for XSS on: {url} ({len(forms)} forms found)")

        for form in forms:
            for payload in XSS_PAYLOADS:
                response = self.submit_form(form, url, payload)
                if response and payload in response.text:
                    print(f"[!] XSS Vulnerability Detected on {url}")
                    print(f"    - Form Action: {form.get('action')}")
                    print(f"    - Injected Payload: {payload}")
                    # Once a vulnerability is found in a form, we can stop testing it
                    break

    def scan_sqli(self, url):
        """
        Scans a URL for SQL Injection (SQLi) vulnerabilities.
        """
        forms = self.get_forms(url)
        print(f"[*] Scanning for SQL Injection on: {url} ({len(forms)} forms found)")
        
        for form in forms:
            for payload in SQLI_PAYLOADS:
                response = self.submit_form(form, url, payload)
                if response:
                    for error in SQLI_ERROR_SIGNATURES:
                        if error in response.text.lower():
                            print(f"[!] SQL Injection Vulnerability Detected on {url}")
                            print(f"    - Form Action: {form.get('action')}")
                            print(f"    - Injected Payload: {payload}")
                            print(f"    - Error Signature: {error}")
                            return # Exit after finding the first vulnerability in the form

    def run_scanner(self):
        """
        Starts the crawling and scanning process.
        """
        print(f"--- Starting Scan on {self.base_url} ---")
        self.crawl()
        
        print(f"\n--- Crawling complete. Found {len(self.discovered_links)} unique links. ---")
        
        for link in self.discovered_links:
            self.scan_xss(link)
            self.scan_sqli(link)
            
        print("\n--- Scan Finished ---")

def main():
    """Main function to parse arguments and initiate the scan."""
    parser = argparse.ArgumentParser(description="A simple web vulnerability scanner.")
    parser.add_argument("url", help="The base URL of the web application to scan.")
    
    args = parser.parse_args()
    
    # Basic URL validation
    if not (args.url.startswith("http://") or args.url.startswith("https://")):
        print("Error: Please provide a full URL including http:// or https://", file=sys.stderr)
        sys.exit(1)
        
    scanner = WebVulnerabilityScanner(args.url)
    scanner.run_scanner()

if __name__ == "__main__":
    main()
