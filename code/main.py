import os
import json
import requests
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pprint import pprint
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL certificate verification warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_domain_availability(domain):
    command = [
        "curl", "-X", "GET", "-H",
        "Authorization: sso-key gHzd25rYwbz7_5robCPAm3XNWzUXkrwrvTb:EosLvhPQqUyoyC2F3CTbJy",
        f"https://api.godaddy.com/v1/domains/available?domain={domain}"
    ]
    try:
        result = subprocess.check_output(command, stderr=subprocess.DEVNULL, universal_newlines=True)
        response = json.loads(result)
        if response.get("available") is True:
            return "Available"
        else:
            return "Domain Taken"
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return "Availability check failed"

def check_dependency_confusion(package_name):
    response = requests.get(f"https://registry.npmjs.com/{package_name}")
    return response.status_code == 404

def search_package_json(directory, perform_dependency_confusion_check=False):
    vulnerable_packages = False  # Flag to track if any package is vulnerable
    package_json_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file == "package.json":
                file_path = os.path.join(root, file)
                package_json_files.append(file_path)

    with ThreadPoolExecutor() as executor:
        futures = []
        for file_path in package_json_files:
            print(f"Found package.json at: {file_path}")
            futures.append(executor.submit(process_package_json, file_path, perform_dependency_confusion_check))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerable_packages = True

    if perform_dependency_confusion_check and not vulnerable_packages:
        print("None of the packages are vulnerable to dependency confusion.")

def process_package_json(file_path, perform_dependency_confusion_check=False):
    with open(file_path) as json_file:
        try:
            data = json.load(json_file)
            dependencies = data.get("dependencies", {})
            dev_dependencies = data.get("devDependencies", {})
            all_dependencies = {**dependencies, **dev_dependencies}
            email_domains = {}

            with ThreadPoolExecutor() as executor:
                futures = []
                for package_name in all_dependencies:
                    futures.append(executor.submit(process_package, package_name, email_domains, perform_dependency_confusion_check))

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        return True

            if not perform_dependency_confusion_check:
                print("Package Dependencies:")
                for package_name, domains in email_domains.items():
                    print(f"{package_name}:")
                    for domain in domains:
                        availability = check_domain_availability(domain)
                        print(f"- {domain}: {availability}")

        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in {file_path}")

    return False

def process_package(package_name, email_domains, perform_dependency_confusion_check):
    package_url = f"https://registry.npmjs.com/{package_name}"
    response = requests.get(package_url)

    if response.status_code == 200:
        package_data = response.json()
        maintainers = package_data.get("maintainers", [])
        for maintainer in maintainers:
            email = maintainer.get("email")
            if email:
                domain = email.split("@")[1]
                if package_name not in email_domains:
                    email_domains[package_name] = set()
                email_domains[package_name].add(domain)
    elif perform_dependency_confusion_check:
        print(f"Checking for dependency confusion for {package_name}:")
        if check_dependency_confusion(package_name):
            print(f"Warning: {package_name} is vulnerable to dependency confusion!")
            return True
        else:
            print(f"{package_name} is not vulnerable to dependency confusion.")

    return False

def perform_code_scanning():
    # Check if snyk is installed
    snyk_installed = not os.system("snyk --version")
    # Install snyk if not already installed
    if not snyk_installed:
        print("snyk is not installed. Installing snyk...")
        os.system("npm install -g snyk")

    # Check if Snyk token file exists
    token_file_path = "snyk_token.txt"
    if os.path.isfile(token_file_path):
        with open(token_file_path, "r") as token_file:
            snyk_token = token_file.read().strip()
    else:
        # Prompt user for Snyk token
        snyk_token = input(
            "Enter Snyk token (token you can get from Snyk account settings page): ")
        with open(token_file_path, "w") as token_file:
            token_file.write(snyk_token)

    # Authenticate with Snyk using the token
    auth_command = f"snyk auth {snyk_token}"
    subprocess.run(auth_command, shell=True)

    print("Performing code scanning...")
    code_scan_command = "snyk code test --all-projects  --show-vulnerable-paths=all"
    try:
        code_scan_output = subprocess.check_output(
            code_scan_command,
            shell=True,
            universal_newlines=True
        )
        # Check if the output is empty
        if code_scan_output.strip():
            # Print code scanning raw output
            print("Code scanning results:")
            print(code_scan_output)
        else:
            print("Code scanning did not produce any output.")
    except subprocess.CalledProcessError as e:
        print("Code scanning failed with the following error:")
        print(e.output)

def perform_dependency_scanning():
    print("Performing dependency scanning...")
    # Check if snyk is installed
    snyk_installed = not os.system("snyk --version")
    # Install snyk if not already installed
    if not snyk_installed:
        print("snyk is not installed. Installing snyk...")
        os.system("npm install -g snyk")

    # Check if Snyk token file exists
    token_file_path = "snyk_token.txt"
    if os.path.isfile(token_file_path):
        with open(token_file_path, "r") as token_file:
            snyk_token = token_file.read().strip()
    else:
        # Prompt user for Snyk token
        snyk_token = input(
            "Enter Snyk token (token you can get from Snyk account settings page): ")
        with open(token_file_path, "w") as token_file:
            token_file.write(snyk_token)

    # Authenticate with Snyk using the token
    auth_command = f"snyk auth {snyk_token}"
    subprocess.run(auth_command, shell=True)

    dependency_scan_command = "snyk test --dev"
    try:
        dependency_scan_output = subprocess.check_output(
            dependency_scan_command,
            shell=True,
            universal_newlines=True
        )
        # Check if the output is empty or not valid JSON
        if dependency_scan_output.strip():
            try:
                dependency_scan_results = json.loads(dependency_scan_output)
                # Print dependency scanning results
                print("Dependency scanning results:")
                pprint(dependency_scan_results)
            except json.JSONDecodeError as e:
                print("Dependency scanning failed. Invalid JSON output.")
                print("Error:", e)
                print("Raw output:")
                print(dependency_scan_output)
        else:
            print("Dependency scanning did not produce any output.")
    except subprocess.CalledProcessError as e:
        print(e.output)

def check_all_buckets(directory):
    # Define the bucket name patterns
    bucket_patterns = {
        "s3": r"(?:(?:s3://|(?:https?://)?[a-z0-9.-]+\.s3(?:\.amazonaws\.com|\.amazonaws\.com\.cn|\.smcloud\.net))[/\?]?[a-z0-9.-]+)",
        "google": r"(?:gs://[^/\s\"']+|google\.storageapis\.com/[^/\s\"']+(?:/[^/\s\"']+)*)",
        "azure": r"(?:https?://)?[^/\s\"']+\.blob\.core\.windows\.net(?:/[^/\s\"']+)?|blob\.core\.windows\.net"
    }

    # Function to search for bucket references in a file
    def search_buckets_in_file(file_path):
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            return {}

        buckets_found = {}
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for bucket_type, pattern in bucket_patterns.items():
                bucket_matches = re.findall(pattern, content, re.IGNORECASE)
                if bucket_matches:
                    buckets_found[bucket_type] = set(bucket_matches)

        return buckets_found

    # Function to search for bucket references in the entire directory content
    def search_buckets_in_directory(directory):
        buckets_found = {}
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_buckets_found = search_buckets_in_file(file_path)
                for bucket_type, buckets in file_buckets_found.items():
                    buckets_found.setdefault(bucket_type, []).extend(
                        [f"{bucket} found in this file {file_path}" for bucket in buckets]
                    )

        return buckets_found

    # Function to check S3 bucket
    def check_s3_bucket(bucket_reference, file_path):
        # Extract the bucket name
        bucket_name = extract_bucket_name(bucket_reference, 's3')
        if not bucket_name:
            return

        # Check the bucket availability
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        response_code = get_response_code(url)
        if response_code == 404:
            # Retry with a different URL
            url = f"https://{bucket_name}.s3.amazonaws.com/x"
            response_code = get_response_code(url)
            print(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")
        else:
            print(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")

    # Function to check Azure bucket
    def check_azure_bucket(bucket_reference, file_path):
        # Extract the bucket name
        bucket_name = extract_bucket_name(bucket_reference, 'azure')
        if not bucket_name:
            return

        # Check the bucket availability
        url = f"https://{bucket_name}.blob.core.windows.net/x"
        response_code = get_response_code(url)
        print(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")

    # Function to check Google bucket
    def check_google_bucket(bucket_reference, file_path):
        # Extract the bucket name
        bucket_name = extract_bucket_name(bucket_reference, 'google')
        if not bucket_name:
            return

        # Check the bucket availability
        url = f"https://storage.googleapis.com/{bucket_name}"
        response_code = get_response_code(url)
        print(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")

    # Function to extract bucket name
    def extract_bucket_name(bucket_reference, bucket_type):
        if bucket_type == 's3':
            match = re.search(r's3://([^/]+)', bucket_reference)
            if match:
                return match.group(1)
            match = re.search(r'([^/]+)\.s3\.amazonaws\.com/([^/]+)', bucket_reference)
            if match:
                return match.group(1)
            match = re.search(r's3\.amazonaws\.com/[^/]+/([^/]+)', bucket_reference)
            if match:
                return match.group(1)
        elif bucket_type == 'azure':
            match = re.search(r'([^/]+)\.blob\.core\.windows\.net', bucket_reference)
            if match:
                return match.group(1)
            match = re.search(r'blob\.core\.windows\.net/([^/]+)', bucket_reference)
            if match:
                return match.group(1)
        elif bucket_type == 'google':
            match = re.search(r'google\.storageapis\.com/([^/]+)', bucket_reference)
            if match:
                return match.group(1)
            match = re.search(r'gs://([^/]+)', bucket_reference)
            if match:
                return match.group(1)

        print(f"Unable to extract bucket name from: {bucket_reference}")
        return None

    # Function to get response code for a given URL
    def get_response_code(url):
        try:
            response = requests.head(url, verify=False)
            return response.status_code
        except RequestException:
            return "Failed to resolve."

    # Search for buckets in the entire directory content
    current_directory = os.getcwd()
    buckets_found = search_buckets_in_directory(current_directory)

    # Print the buckets found
    for bucket_type, buckets in buckets_found.items():
        print(f"{bucket_type.capitalize()} Buckets:")
        if buckets:
            for i, bucket in enumerate(buckets, start=1):
                print(f"{i}. {bucket}")
        else:
            print(f"No {bucket_type.capitalize()} buckets found in the repository.")

    # Check each bucket's availability
    for bucket_type, buckets in buckets_found.items():
        print(f"\nChecking {bucket_type.capitalize()} buckets:")
        for bucket_reference in buckets:
            file_path = bucket_reference.split(" found in this file ")[1]
            if bucket_type == "s3":
                check_s3_bucket(bucket_reference.split(" found in this file ")[0], file_path)
            elif bucket_type == "azure":
                check_azure_bucket(bucket_reference.split(" found in this file ")[0], file_path)
            elif bucket_type == "google":
                check_google_bucket(bucket_reference.split(" found in this file ")[0], file_path)

def perform_all_actions(directory):
    print("Performing all actions...")
    search_package_json(directory)
    search_package_json(directory, perform_dependency_confusion_check=True)
    perform_code_scanning()
    perform_dependency_scanning()
    check_all_buckets(directory)

def show_menu():
    print("Select an option:")
    print("1. Check for abundant domains emails in package.json")
    print("2. Check for dependency confusion in package.json")
    print("3. Perform code scanning")
    print("4. Perform dependency scanning")
    print("5. Check for all buckets in a repo and check if buckets exist or not")
    print("6. Do everything")
    print("7. Exit")
    choice = input("Enter your choice (1-7): ")
    return choice

def handle_option(option, directory):
    if option == '1':
        search_package_json(directory)
    elif option == '2':
        # Implement dependency confusion check
        search_package_json(directory, perform_dependency_confusion_check=True)
    elif option == '3':
        perform_code_scanning()
    elif option == '4':
        perform_dependency_scanning()
    elif option == '5':
        check_all_buckets(directory)
    elif option == '6':
        perform_all_actions(directory)
    else:
        print("Invalid option. Please choose a number from 1 to 6.")


# Get user input for repository URL
repo_url = input("Enter GitHub repo URL: ")
response = requests.get(repo_url)

# Check if repository exists
if response.status_code == 200:
    print("Downloading repo...")
    os.system(f"git clone {repo_url}")
else:
    pat = input("Enter GitHub personal access token: ")
    repo_url = repo_url.replace("https://", "", 1)
    cloned_url = f"https://{pat}@{repo_url.split('.git/')[0]}"
    os.system(f"git clone {cloned_url}")

repo_name = os.path.basename(repo_url.rstrip("/"))
print(repo_name)

try:
    os.chdir(repo_name)
except FileNotFoundError:
    print("Failed to navigate to the cloned repository.")
    exit(1)

current_directory = os.getcwd()

# Main loop
while True:
    # Show menu options and handle user choice
    option = show_menu()
    if option == '7':
        print("Exiting the program.")
        break
    handle_option(option, current_directory)


#https://github.com/uber/athenadriver