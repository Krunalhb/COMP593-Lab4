import sys
import re 
from log_functions import get_log_file_path, filter_log_messages
import csv
import os


# TODO: Step 3
def get_log_file_path():
    if len(sys.argv) < 2:
        print("Error: no log file path provided.")
        sys.exit(1)
    return sys.argv[1]


# TODO: Steps 4-7
#Step-4
def filter_log_by_regex(log_file_path, regex, case_sensitive=True, print_summary=False, print_matching=False):
    with open(log_file_path, 'r') as log_file:
        log_data = log_file_path.read()
        if not case_sensitive:
            regex = "(?i)" + regex  # add case-insensitive flag to regex
        matches = re.findall(regex, log_data)
        if print_matching:
            for match in matches:
                print(match)
        if print_summary:
            case_match_str = "case-sensitive" if case_sensitive else "case-insensitive"
            print(f"{len(matches)} records matched the '{regex}' regex ({case_match_str}).")
        return matches
def main():
    log_path = log_file_path()
    filter_log_records(log_path, "SRC=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", print_matching=True, print_summary=True)

#Step-5
# 1: Get the log file path
log_file_path = get_log_file_path()

# 2: Define the regex patterns to search for
regex1 = 'sshd'
regex2 = 'invalid user'
regex3 = 'error'
regex4 = 'pam'

# 3: Filter records that match the regex 'sshd' and print them
print("\nRecords that match the regex 'sshd':")
filter_log_messages(log_file_path, regex1, False, True, True)

# 4: Filter records that match the regex 'invalid user' and print them
print("\nRecords that match the regex 'invalid user':")
filter_log_messages(log_file_path, regex2, False, True, True)

# 5: Filter records that match the regex 'error' and print them
print("\nRecords that match the regex 'error':")
filter_log_messages(log_file_path, regex3, False, True, True)

# 6: Filter records that match the regex 'pam' and print them
print("\nRecords that match the regex 'pam':")
filter_log_messages(log_file_path, regex4, False, True, True)

#Step 6
def get_log_file_path(args):
    """
    Extracts the log file path from the command line arguments.

    Args:
        args: A list of command line arguments.

    Returns:
        The log file path.
    """
    if len(args) < 2:
        print("Please provide a log file path.")
        exit(1)

    return args[1]


def filter_log_file(log_file_path, regex, case_sensitive=True, print_matches=False, print_summary=False):
    """
    Filters a log file for records matching a regular expression.

    Args:
        log_file_path: The path to the log file.
        regex: The regular expression to match.
        case_sensitive: Whether to perform a case-sensitive match (default: True).
        print_matches: Whether to print the matched records (default: False).
        print_summary: Whether to print a summary of the matched records (default: False).

    Returns:
        A list of the matched log records.
    """
    with open(log_file_path, "r") as f:
        log_data = f.read()

    flags = re.IGNORECASE if not case_sensitive else 0
    matches = re.findall(regex, log_data, flags=flags)

    if print_matches:
        for match in matches:
            print(match)

    if print_summary:
        num_matches = len(matches)
        case_sensitivity = "case-insensitive" if not case_sensitive else "case-sensitive"
        print(f"Found {num_matches} {case_sensitivity} matches for regex '{regex}'")

    return matches

#Step-7
def filter_log_records(log_file_path, regex, case_sensitive=False, print_matching_records=False, print_summary=False):
    with open(log_file_path, 'r') as log_file:
        records = log_file.read().split('\n')
        
    matching_records = []
    extracted_data = []
    for record in records:
        if case_sensitive:
            match = re.search(regex, record)
        else:
            match = re.search(regex, record, re.IGNORECASE)
        if match:
            matching_records.append(record)
            if match.groups():
                extracted_data.append(match.groups())

    if print_matching_records:
        for record in matching_records:
            print(record)

    num_matching_records = len(matching_records)
    if print_summary:
        print(f"Found {num_matching_records} matching records. Case {'sensitive' if case_sensitive else 'insensitive'} regex matching was performed.")
        
    return matching_records, extracted_data
# TODO: Step 8
def tally_port_traffic(log_file):
    with open(log_file_path, 'r') as log_file:
        port_tallies = {}
        for line in log_file:
            if "DPT=" in line:
                match = re.search(r'DPT=(\d+)', line)
                if match:
                    port = int(match.group(1))
                    port_tallies[port] = port_tallies.get(port, 0) + 1
    return port_tallies

# TODO: Step 9
def generate_port_traffic_report(log_file_path, port_number):
    # Process the log file to create a dictionary of record tallies for each destination port
    port_counts = process_log_file(log_file_path)
    

    # Get the number of records for the specified port number
    count = port_counts.get(port_number, 0)

    # Generate the CSV file
    file_name = f"destination_port_{port_number}_report.csv"
    with open(file_name, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Destination Port", "Count"])
        writer.writerow([port_number, count])

    print(f"Report generated: {file_name}")
    return

#Step 10
def main():
    # get log file path from command line argument
    log_file_path = get_log_file_path()

    # create dictionary of record tallies for each destination port
    destination_port_tallies = destination_port_tallies(log_file_path)

    # generate report for each port with a record count of 100 or more
    for port, count in destination_port_tallies.items():
        if count >= 100:
            port(log_file_path, port)

# TODO: Step 11
def generate_invalid_users_report(log_file_path):
    # Define the regular expression pattern to match invalid user records
    pattern = r"Invalid user (.+) from (\d+\.\d+\.\d+\.\d+)"

    # Open the log file
    with open(log_file_path, "r") as log_file:
        # Read the log file line by line
        lines = log_file.readlines()

    # Use a dictionary to count the number of invalid user records for each IP address
    invalid_user_counts = {}
    for line in lines:
        match = re.search(pattern, line)
        if match:
            username = match.group(1)
            ip_address = match.group(2)
            if ip_address in invalid_user_counts:
                invalid_user_counts[ip_address] += 1
            else:
                invalid_user_counts[ip_address] = 1

    # Generate the report CSV file
    report_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "invalid_users.csv")
    with open(report_file_path, "w", newline="") as report_file:
        writer = csv.writer(report_file)
        writer.writerow(["IP Address", "Invalid User Count"])
        for ip_address, count in invalid_user_counts.items():
            writer.writerow([ip_address, count])

    print(f"Invalid user report generated and saved to {report_file_path}")
    return
def main():
    log_file_path = "/path/to/log/file"
    generate_invalid_users_report(log_file_path)

if __name__ == "__main__":
    main()

# TODO: Step 12
def generate_source_ip_log(log_file_path, source_ip_address):
    log_file = open(log_file_path, 'r')
    output_file_path = f"source_ip_{source_ip_address.replace('.', '_')}.log"
    output_file = open(output_file_path, 'w')
    pattern = f"SRC={source_ip_address}"
    
    for line in log_file:
        if re.search(pattern, line):
            output_file.write(line)
            
    output_file.close()
    log_file.close()
    return

if __name__ == '__main__':
    main()