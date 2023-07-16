from colorama import Fore, Style
import socket
import ssl
import requests
import builtwith
import whois
from bs4 import BeautifulSoup

def print_ascii_art():
    print(f"{Fore.RED}")
    print(" __   __  ___   _______   _______     _______     _______    ______       ______     _____  ___   ")
    print("|\"  |/  \|  \"| /\"     \"| |   _  \"\   /\"      \   /\"     \"|  /\" _  \"\     /    \" \   (\"\"   \|  \"\  ")
    print("|'  /    \:  |(: ______) (. |_)  :) |:        | (: ______) (: ( \___)   // ____  \  |.\\\\   \    | ")
    print("|: /'        | \/    |   |:     \/  |_____/   )  \/    |    \/ \       /  /    ) :) |: \.   \\\\  | ")
    print("\\//  /\\'    | // ___)_  (|  _  \\\\   //      /   // ___)_   //  \\ _   (: (____/ //  |.  \\    \\. | ")
    print("/   /  \\\\   |(:      \"| |: |_)  :) |:  __   \  (:      \"| (:   _) \\   \\        /   |    \\    \\ | ")
    print("|___/    \\___| \\_______) (_______/  |__|  \\___)  \\_______)  \\_______)   \\\"_____/     \\___|\\____\\) ")
    print("                                                                                                  ")
    print(f"{Style.RESET_ALL}")

def extract_website_info(url):
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')

        website_title = soup.title.text
        website_url = url
        website_description = soup.find('meta', {'name': 'description'})['content']

        page_headings = [heading.text for heading in soup.find_all(['h1', 'h2', 'h3'])]

        internal_links = [link['href'] for link in soup.find_all('a', href=True) if not link['href'].startswith('http')]
        external_links = [link['href'] for link in soup.find_all('a', href=True) if link['href'].startswith('http')]

        navigation_menu_items = [item.text.strip() for item in soup.find_all('nav')]
        footer_info = soup.find('footer').text.strip()

        print(f"{Fore.GREEN}Website Information{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Website Title:{Style.RESET_ALL} {website_title}")
        print(f"{Fore.CYAN}Website URL:{Style.RESET_ALL} {website_url}")
        print(f"{Fore.CYAN}Website Description:{Style.RESET_ALL} {website_description}")

        print(f"\n{Fore.GREEN}Navigation Menu{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Navigation Menu Items:{Style.RESET_ALL}")
        for item in navigation_menu_items:
            print(f"  - {item}")

        print(f"\n{Fore.GREEN}Footer Information{Style.RESET_ALL}")
        print(footer_info)

        print(f"\n{Fore.GREEN}Internal Links{Style.RESET_ALL}")
        for link in internal_links:
            print(f"  - {link}")

        print(f"\n{Fore.GREEN}External Links{Style.RESET_ALL}")
        for link in external_links:
            print(f"  - {link}")

    else:
        print(f"{Fore.RED}Error accessing the URL. Status code:{Style.RESET_ALL}", response.status_code)

def analyze_website(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(domain)

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = cert['notAfter']
                issuer = dict(item[0] for item in cert['issuer'])

        response = requests.get(url)
        server = response.headers.get('server')

        tech_stack = builtwith.builtwith(url)

        whois_info = whois.whois(domain)

        print(f"\n{Fore.GREEN}Website Information{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Domain:{Style.RESET_ALL} {domain}")
        print(f"{Fore.CYAN}IP Address:{Style.RESET_ALL} {ip_address}")
        print(f"{Fore.CYAN}Server:{Style.RESET_ALL} {server}")
        print(f"{Fore.CYAN}SSL Certificate - Expiry Date:{Style.RESET_ALL} {expiry_date}")
        print(f"{Fore.CYAN}SSL Certificate - Issuer:{Style.RESET_ALL} {issuer}")

        print(f"\n{Fore.GREEN}Technologies Used{Style.RESET_ALL}")
        for category, tech_list in tech_stack.items():
            print(f"{Fore.CYAN}{category}:{Style.RESET_ALL}")
            for tech in tech_list:
                print(f"  - {tech}")

        print(f"\n{Fore.GREEN}Whois Information{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Name:{Style.RESET_ALL} {whois_info.name}")
        print(f"{Fore.CYAN}Email:{Style.RESET_ALL} {whois_info.email}")
        print(f"{Fore.CYAN}Creation Date:{Style.RESET_ALL} {whois_info.creation_date}")
        print(f"{Fore.CYAN}Expiration Date:{Style.RESET_ALL} {whois_info.expiration_date}")

    except Exception as e:
        print(f"{Fore.RED}Error occurred: {str(e)}{Style.RESET_ALL}")

def main():
    print_ascii_art()
    print(f"{Fore.YELLOW}WebRecon - Website Information Tool{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Author: Angshuman Phonglo 🎸{Style.RESET_ALL}")
    url = input("Enter the website URL: ")
    analyze_website(url)
    extract_website_info(url)

if __name__ == "__main__":
    main()
