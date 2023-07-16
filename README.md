from colorama import Fore, Style
import socket
import ssl
import requests
import builtwith
import whois

def print_ascii_art():
    print("""
   ____                  _     ____        _   
  / ___|_ __ _   _ _ __ | |_  / ___| _ __ (_)_ 
 | |  _| '__| | | | '_ \| __| \___ \| '_ \| | |
 | |_| | |  | |_| | |_) | |_   ___) | |_) | | |
  \____|_|   \__, | .__/ \__| |____/| .__/|_|_|
            |___/|_|              |_|        
    """)

def analyze_website(url):
    try:
        # Extract domain from the URL
        domain = url.split("//")[-1].split("/")[0]

        # Get IP address of the domain
        ip_address = socket.gethostbyname(domain)

        # Perform SSL handshake and retrieve certificate details
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = cert['notAfter']
                issuer = dict(item[0] for item in cert['issuer'])

        # Perform a simple GET request to gather server information
        response = requests.get(url)
        server = response.headers.get('server')

        # Use builtwith to determine the technologies used
        tech_stack = builtwith.builtwith(url)

        # Use whois to retrieve domain registration information
        whois_info = whois.whois(domain)

        # Display the gathered information
        print(f"{Fore.GREEN}Website Information{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Domain:{Style.RESET_ALL} {domain}")
        print(f"{Fore.CYAN}IP Address:{Style.RESET_ALL} {ip_address}")
        print(f"{Fore.CYAN}Server:{Style.RESET_ALL} {server}")
        print(f"{Fore.CYAN}SSL Certificate - Expiry Date:{Style.RESET_ALL} {expiry_date}")
        print(f"{Fore.CYAN}SSL Certificate - Issuer:{Style.RESET_ALL} {issuer}")

        print(f"{Fore.GREEN}Technologies Used{Style.RESET_ALL}")
        for category, tech_list in tech_stack.items():
            print(f"{Fore.CYAN}{category}:{Style.RESET_ALL} {', '.join(tech_list)}")

        print(f"{Fore.GREEN}Whois Information{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Name:{Style.RESET_ALL} {whois_info.name}")
        print(f"{Fore.CYAN}Email:{Style.RESET_ALL} {whois_info.email}")
        print(f"{Fore.CYAN}Creation Date:{Style.RESET_ALL} {whois_info.creation_date}")
        print(f"{Fore.CYAN}Expiration Date:{Style.RESET_ALL} {whois_info.expiration_date}")

    except Exception as e:
        print(f"{Fore.RED}Error occurred: {str(e)}{Style.RESET_ALL}")

def main():
    print_ascii_art()
    print(f"{Fore.GREEN}WebRecon - Website Information Tool")
    print(f"Author: Angshuman Phonglo{Style.RESET_ALL}\n")
    url = input("Enter the website URL: ")
    analyze_website(url)

if __name__ == "__main__":
    main()
