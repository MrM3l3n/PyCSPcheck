import aiohttp
import asyncio
import json
import logging
from urllib.parse import urlparse
from colorama import Fore, Style, init
import os
import pyfiglet

# Initialize colorama
init(autoreset=True)

# Script Title
SCRIPT_TITLE = "PYCSPCHECKER"
SCRIPT_DESCRIPTION = "A Python script to analyze and validate Content Security Policy (CSP) headers for websites."

# Function to print the title in large ASCII art
def print_title():
    large_title = pyfiglet.figlet_format(SCRIPT_TITLE)
    print(f"{Fore.GREEN}{large_title}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{SCRIPT_DESCRIPTION}{Style.RESET_ALL}")

# Print the title and description
print_title()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Asynchronous function to fetch headers and extract CSP
async def get_csp(session, url):
    try:
        async with session.get(url, timeout=3) as response:
            headers = response.headers
            if 'Content-Security-Policy' in headers:
                return headers['Content-Security-Policy'], False
            elif 'Content-Security-Policy-Report-Only' in headers:
                return headers['Content-Security-Policy-Report-Only'], True
            else:
                return None, False
    except asyncio.TimeoutError:
        logger.error(f"Timeout while fetching {url}")
        raise Exception(f"{Fore.RED}Error: Timeout while fetching {url}.{Style.RESET_ALL}")
    except aiohttp.ClientError as e:
        logger.error(f"Network Error for {url}: {e}")
        raise Exception(f"{Fore.RED}Network Error for {url}: {e}{Style.RESET_ALL}")

# Function to send asynchronous requests with rate limiting
async def try_connect_with_retries(url, max_retries=10, delay=1):
    attempts = 0
    async with aiohttp.ClientSession() as session:
        while attempts < max_retries:
            try:
                logger.info(f"Attempt {attempts + 1} to connect to {url}...")
                return await get_csp(session, url)
            except Exception as e:
                print(f"{Fore.RED}Attempt {attempts + 1} failed: {e}{Style.RESET_ALL}")
                attempts += 1
                await asyncio.sleep(delay)  # Rate limiting: wait before retrying
    logger.error(f"Failed to connect to {url} after {max_retries} attempts.")
    raise Exception(f"{Fore.RED}Failed to connect to {url} after {max_retries} attempts.{Style.RESET_ALL}")

# Function to categorize CSP by directive type
def categorize_csp(csp):
    categories = {
        "default-src": "Default Source",
        "script-src": "Script Source",
        "style-src": "Style Source",
        "img-src": "Image Source",
        "connect-src": "Connect Source",
        "font-src": "Font Source",
        "frame-src": "Frame Source",
        "media-src": "Media Source",
        "object-src": "Object Source",
        "child-src": "Child Source",
        "form-action": "Form Actions",
        "report-uri": "Reporting URI",
        "upgrade-insecure-requests": "Insecure Requests Handling",
        "block-all-mixed-content": "Mixed Content Blocking",
        "frame-ancestors": "Frame Ancestors",
        "manifest-src": "Manifest Source",
        "script-src-elem": "Script Source Element",
        "script-src-attr": "Script Source Attribute",
        "style-src-elem": "Style Source Element",
        "style-src-attr": "Style Source Attribute",
        "worker-src": "Worker Source",
        "navigate-to": "Navigation Source",
        "base-uri": "Base URI"
    }

    # Split the CSP into directives
    directives = csp.split(';')
    categorized = {cat: [] for cat in categories.values()}

    # Loop through directives and categorize them
    for directive in directives:
        directive = directive.strip()
        if directive:
            directive_name = directive.split(' ')[0]
            if directive_name in categories:
                categorized[categories[directive_name]].append(directive)
            else:
                categorized.setdefault("Other Directives", []).append(directive)
    
    return categorized

# Function to evaluate CSP for unsafe directives
def evaluate_csp(csp):
    issues = []
    
    # Check for unsafe directives
    if "unsafe-inline" in csp:
        issues.append(f"{Fore.RED}Warning: 'unsafe-inline' is present, which allows execution of inline scripts and styles.{Style.RESET_ALL}")
    if "unsafe-eval" in csp:
        issues.append(f"{Fore.RED}Warning: 'unsafe-eval' is present, which allows the use of JavaScript's eval().{Style.RESET_ALL}")
    if "*" in csp:
        issues.append(f"{Fore.RED}Warning: Wildcard (*) is used in the CSP, which can allow resources from any origin.{Style.RESET_ALL}")
    
    # Check for dangerous directives
    if "data:" in csp:
        issues.append(f"{Fore.RED}Warning: 'data:' is present, which can allow data URI resources and could lead to attacks.{Style.RESET_ALL}")
    if "blob:" in csp:
        issues.append(f"{Fore.RED}Warning: 'blob:' is present, which can allow Blob URL resources and might be exploited.{Style.RESET_ALL}")
    if "http:" in csp and "https:" not in csp:
        issues.append(f"{Fore.RED}Warning: 'http:' is present without 'https:', which may allow insecure resource loading.{Style.RESET_ALL}")
    
    # Check for reporting directives
    if "report-uri" in csp:
        issues.append(f"{Fore.YELLOW}Info: 'report-uri' directive is present. Ensure that the reporting endpoint is secure and monitored.{Style.RESET_ALL}")
    if "report-to" in csp:
        issues.append(f"{Fore.YELLOW}Info: 'report-to' directive is present. Ensure that the reporting endpoint is secure and monitored.{Style.RESET_ALL}")

    # Other best practices
    if "frame-ancestors" not in csp:
        issues.append(f"{Fore.YELLOW}Info: Consider adding a 'frame-ancestors' directive to prevent clickjacking.{Style.RESET_ALL}")
    if "upgrade-insecure-requests" not in csp:
        issues.append(f"{Fore.YELLOW}Info: Consider adding 'upgrade-insecure-requests' to enforce HTTPS for requests.{Style.RESET_ALL}")

    return issues
    
# Function to display the categorized CSP
def display_categorized_csp(categorized_csp):
    output = []
    for category, directives in categorized_csp.items():
        if directives:
            output.append(f"{Fore.YELLOW}{category}:{Style.RESET_ALL}")
            for directive in directives:
                output.append(f"  - {directive}")
            output.append("")  # For spacing
    return "\n".join(output)

# Function to output results in the chosen format
def output_results(results, output_format='text'):
    if output_format == 'json':
        return json.dumps(results, indent=2)
    else:
        return "\n".join(results)

# Function to save results to a file
def save_results_to_file(results, filename):
    with open(filename, 'w') as file:
        file.write(results)
    print(f"Results saved to {filename}")

# Function to get a valid filename from the user
def get_filename():
    for attempt in range(3):
        filename = input("Enter a filename to save the results (with .txt or .json extension): ").strip()
        if filename.endswith(('.txt', '.json')):
            return filename
        else:
            print(f"{Fore.RED}Error: Filename must end with .txt or .json.{Style.RESET_ALL}")
            if attempt < 2:
                print(f"Please try again. Attempt {attempt + 2} of 3.")
    print(f"{Fore.RED}Exiting due to invalid filename input.{Style.RESET_ALL}")
    exit()

# Main function to run the script
async def main(urls, output_format='text', save_to_file=False, timeout=3, max_retries=10):
    results = []
    
    for url in urls:
        print(f"Checking {url}...")
        parsed_url = urlparse(url)
        
        # Automatically use HTTPS for URLs
        if parsed_url.scheme == '' or parsed_url.scheme == 'http':
            # If it's an HTTP URL, prompt user to confirm
            if parsed_url.scheme == 'http':
                use_http = input(f"{Fore.YELLOW}You entered an HTTP URL: {url}. Would you like to use HTTP instead of HTTPS? (yes/no): ").strip().lower()
                if use_http == 'yes':
                    pass  # Keep the URL as is
                else:
                    url = url.replace('http://', 'https://')  # Convert to HTTPS
            else:
                url = f"https://{url}"  # Convert to HTTPS

        try:
            csp, report_only = await try_connect_with_retries(url, max_retries=max_retries)
            
            if csp:
                result = f"CSP found for {url}:\n"
                if report_only:
                    result += f"{Fore.YELLOW}CSP found for {url} (Report-Only mode):{Style.RESET_ALL}\n"
                
                categorized_csp = categorize_csp(csp)
                result += f"{Fore.YELLOW}Categorized CSP:{Style.RESET_ALL}\n"
                result += display_categorized_csp(categorized_csp)
                
                issues = evaluate_csp(csp)
                if issues:
                    result += f"{Fore.RED}\nPotential Security Issues Detected:{Style.RESET_ALL}\n"
                    for issue in issues:
                        result += f"  - {issue}\n"
                else:
                    result += "\nNo major security issues detected in the CSP."
            else:
                result = f"No CSP found for {url}."
            
            results.append(result)
        
        except Exception as e:
            results.append(str(e))
        
        await asyncio.sleep(1)

    final_output = output_results(results, output_format)

    if save_to_file:
        filename = get_filename()  # Get a valid filename from the user
        save_results_to_file(final_output, filename)
    else:
        print(final_output)

# Example usage
if __name__ == "__main__":
    urls_to_check = input("Enter the website URLs (comma separated): ").split(',')
    urls_to_check = [url.strip() for url in urls_to_check]
    output_format = input("Choose output format (text/json): ").strip().lower()
    
    save_choice = input("Do you want to save the output to a file? (yes/no): ").strip().lower()
    save_to_file = save_choice == 'yes'

    # Get timeout and max retries from the user
    timeout = int(input("Enter the timeout for requests (in seconds): ").strip())
    max_retries = int(input("Enter the maximum number of retries for failed requests: ").strip())

    asyncio.run(main(urls_to_check, output_format, save_to_file, timeout, max_retries))