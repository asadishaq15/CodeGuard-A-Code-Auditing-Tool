

from flask import Flask, render_template, request, jsonify
import os
import json
import requests
import re
from flask_cors import CORS
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pprint import pprint
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
from flask_socketio import SocketIO, emit, join_room, leave_room

# Suppress SSL certificate verification warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'codeGuard'
socketio = SocketIO(app, cors_allowed_origins="http://localhost:5173")
CORS(app)
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def send_output(output):
    socketio.emit('output', output)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/perform_actions', methods=['POST'])
def perform_actions():
    data = request.get_json()  # Parse JSON data from request body
    repo_url = data.get('repo_url')
    action = data.get('action')
    snyk_token = data.get('snykToken')  # Get the Snyk token from the request data
    if repo_url and action:
        directory = clone_repository(repo_url)
        if directory:
            if action == '1':
                send_output("Searching for package.json files...")
                result = search_package_json(directory)
            elif action == '2':
                send_output("Searching for package.json files and checking for dependency confusion...")
                result = search_package_json(directory, perform_dependency_confusion_check=True)
            elif action == '3':
                send_output("Performing code scanning...")
                result = perform_code_scanning(snyk_token)  # Pass the Snyk token to the function
            elif action == '4':
                result = perform_dependency_scanning(repo_url, snyk_token)  # Pass the Snyk token to the function
            elif action == '5':
                send_output("Checking all buckets...")
                result = check_all_buckets(directory)
            elif action == '6':
                send_output("Performing all actions...")
                result = perform_all_actions(directory, snyk_token)  # Pass the Snyk token to the function
            else:
                result = "Invalid action selected."

            return jsonify({'result': result}), 200  # Return the result as a JSON response with a 200 OK status code
        else:
            return jsonify({'error': 'Failed to clone repository.'}), 400
    else:
        return jsonify({'error': 'Missing required fields.'}), 400


def clone_repository(repo_url):
    response = requests.get(repo_url)
    if response.status_code == 200:
        send_output("Repository URL is accessible. Downloading repository...")
        os.system(f"git clone {repo_url}")
        repo_name = os.path.basename(repo_url.rstrip("/"))
        send_output(f"Repository cloned: {repo_name}")
        try:
            os.chdir(repo_name)
            send_output(f"Navigated to the cloned repository: {os.getcwd()}")
            return os.getcwd()
        except FileNotFoundError:
            send_output("Failed to navigate to the cloned repository.")
            return None
    else:
        send_output("Repository URL is not accessible. Requesting personal access token...")
        pat = input("Enter GitHub personal access token: ")
        repo_url = repo_url.replace("https://", "", 1)
        cloned_url = f"https://{pat}@{repo_url.split('.git/')[0]}"
        send_output("Cloning repository with personal access token...")
        os.system(f"git clone {cloned_url}")
        repo_name = os.path.basename(repo_url.rstrip("/"))
        send_output(f"Repository cloned: {repo_name}")
        try:
            os.chdir(repo_name)
            send_output(f"Navigated to the cloned repository: {os.getcwd()}")
            return os.getcwd()
        except FileNotFoundError:
            send_output("Failed to navigate to the cloned repository.")
            print("Failed to navigate to the cloned repository.")
            return None

def search_package_json(directory, perform_dependency_confusion_check=False):
    vulnerable_packages = False  # Flag to track if any package is vulnerable
    package_json_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file == "package.json":
                file_path = os.path.join(root, file)
                package_json_files.append(file_path)
                send_output(f"Found package.json at: {file_path}")

    with ThreadPoolExecutor() as executor:
        futures = []
        for file_path in package_json_files:
            futures.append(executor.submit(process_package_json, file_path, perform_dependency_confusion_check))

        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerable_packages = True

    if perform_dependency_confusion_check and not vulnerable_packages:
        send_output("None of the packages are vulnerable to dependency confusion.")

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
                send_output("Package Dependencies:")
                for package_name, domains in email_domains.items():
                    send_output(f"{package_name}:")
                    for domain in domains:
                        availability = check_domain_availability(domain)
                        send_output(f"- {domain}: {availability}")

        except json.JSONDecodeError:
            send_output(f"Error: Invalid JSON format in {file_path}")

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
        send_output(f"Checking for dependency confusion for {package_name}:")
        if check_dependency_confusion(package_name):
            send_output(f"Warning: {package_name} is vulnerable to dependency confusion!")
            return True
        else:
            send_output(f"{package_name} is not vulnerable to dependency confusion.")

    return False

def check_dependency_confusion(package_name):
    response = requests.get(f"https://registry.npmjs.com/{package_name}")
    return response.status_code == 404

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
            availability = "Available"
        else:
            availability = "Domain Taken"
        send_output(f"Domain availability: {domain} - {availability}")
        return availability
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        send_output(f"Availability check failed for domain: {domain}")
        return "Availability check failed"
    
def perform_code_scanning(snyk_token):
    # Check if snyk is installed
    snyk_installed = not os.system("snyk --version")
    # Install snyk if not already installed
    if not snyk_installed:
        send_output("snyk is not installed. Installing snyk...")
        os.system("npm install -g snyk")
        send_output("snyk installed successfully.")

    # Authenticate with Snyk using the token
    send_output("Authenticating with Snyk...")
    auth_command = f"snyk auth {snyk_token}"
    subprocess.run(auth_command, shell=True)
    send_output("Authentication with Snyk successful.")

    send_output("Performing code scanning...")
    code_scan_command = "snyk code test --all-projects  --show-vulnerable-paths=all"
    try:
        code_scan_output = subprocess.check_output(
            code_scan_command,
            shell=True,
            universal_newlines=True
        )
        # Check if the output is empty
        if code_scan_output.strip():
            send_output("Code scanning results:")
            for line in code_scan_output.split('\n'):
                send_output(line)
        else:
            send_output("Code scanning did not produce any output.")
    except subprocess.CalledProcessError as e:
        send_output("Code scanning failed with the following error:")
        for line in e.output.split('\n'):
            send_output(line)

def perform_dependency_scanning(repo_url, snyk_token):
    send_output("Performing dependency scanning...")
    # Check if snyk is installed
    snyk_installed = not os.system("snyk --version")
    # Install snyk if not already installed
    if not snyk_installed:
        send_output("snyk is not installed. Installing snyk...")
        os.system("npm install -g snyk")
        send_output("snyk installed successfully.")

    # Authenticate with Snyk using the token
    send_output("Authenticating with Snyk...")
    auth_command = f"snyk auth {snyk_token}"
    subprocess.run(auth_command, shell=True)
    send_output("Authentication with Snyk successful.")

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
                send_output("Dependency scanning results:")
                for line in json.dumps(dependency_scan_results, indent=2).split('\n'):
                    send_output(line)
            except json.JSONDecodeError as e:
                send_output("Dependency scanning failed. Invalid JSON output.")
                send_output("Error:", e)
                send_output("Raw output:")
                for line in dependency_scan_output.split('\n'):
                    send_output(line)
        else:
            send_output("Dependency scanning did not produce any output.")
    except subprocess.CalledProcessError as e:
        for line in e.output.split('\n'):
            send_output(line)

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
            send_output(f"File not found: {file_path}")
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
                send_output(f"Searching for buckets in file: {file_path}")
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
            send_output(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")
        else:
            send_output(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")

    # Function to check Azure bucket
    def check_azure_bucket(bucket_reference, file_path):
        # Extract the bucket name
        bucket_name = extract_bucket_name(bucket_reference, 'azure')
        if not bucket_name:
            return

        # Check the bucket availability
        url = f"https://{bucket_name}.blob.core.windows.net/x"
        response_code = get_response_code(url)
        send_output(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")

    # Function to check Google bucket
    def check_google_bucket(bucket_reference, file_path):
        # Extract the bucket name
        bucket_name = extract_bucket_name(bucket_reference, 'google')
        if not bucket_name:
            return

        # Check the bucket availability
        url = f"https://storage.googleapis.com/{bucket_name}"
        response_code = get_response_code(url)
        send_output(f"{bucket_reference} found in this file {file_path}, {response_code} Response code.")

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

        send_output(f"Unable to extract bucket name from: {bucket_reference}")
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

def perform_all_actions(directory, snyk_token):
    print("Performing all actions...")
    search_package_json(directory)
    search_package_json(directory, perform_dependency_confusion_check=True)
    perform_code_scanning(snyk_token)
    perform_dependency_scanning(repo_url, snyk_token)
    check_all_buckets(directory)

    for line in output.split('\n'):
        socketio.emit('output', line)

if __name__ == '__main__':
    socketio.run(app, debug=True)
    app.run(debug=True)