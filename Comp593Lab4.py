import sys
import os
import re
import csv

def main(log_file_path):
    log_file = get_log_file_path_from_param(log_file_path)

    # Step 5:
    print("Checking for SSHD records...")
    sshd_records, _ = filter_log_by_regex(log_file, 'sshd', ignore_case=True, print_summary=True, print_records=True)

    print("Checking for invalid user records...")
    invalid_user_records, _ = filter_log_by_regex(log_file, 'invalid user', ignore_case=True, print_summary=True, print_records=True)

    print("Checking for specific invalid user IP records...")
    specific_invalid_user_records, _ = filter_log_by_regex(log_file, 'invalid user.*220.195.35.40', ignore_case=True, print_summary=True, print_records=True)

    print("Checking for error records...")
    error_records, _ = filter_log_by_regex(log_file, 'error', ignore_case=True, print_summary=True, print_records=True)

    print("Checking for PAM records...")
    pam_records, _ = filter_log_by_regex(log_file, 'pam', ignore_case=True, print_summary=True, print_records=True)

    # Step 10: 
    port_traffic = tally_port_traffic(log_file)
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_file, port)

    # Step 11: 
    generate_invalid_user_report(log_file)

    # Step 12: 
    generate_source_ip_log(log_file, '220.195.35.40')

def get_log_file_path_from_param(log_file_path):
    if not os.path.isfile(log_file_path):
        print(f"Error: The file '{log_file_path}' does not exist.")
        sys.exit(1)
    return log_file_path

def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    flags = re.IGNORECASE if ignore_case else 0
    pattern = re.compile(regex, flags)
    matching_records = []
    captured_data = []

    with open(log_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                matching_records.append(line.strip())
                captured_data.append(match.groups())

    if print_records:
        for record in matching_records:
            print(record)

    if print_summary:
        summary = f"The log file contains {len(matching_records)} records that {'case-insensitive' if ignore_case else 'case-sensitive'} match the regex \"{regex}\"."
        print(summary)

    return matching_records, captured_data

def tally_port_traffic(log_file):
    port_traffic = {}

    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = match.group(1)
                if port in port_traffic:
                    port_traffic[port] += 1
                else:
                    port_traffic[port] = 1

    return port_traffic

def generate_port_traffic_report(log_file, port):
    report_file = f"destination_port_{port}_report.csv"

    with open(log_file, 'r') as file, open(report_file, 'w', newline='') as csvfile:
        fieldnames = ['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for line in file:
            match = re.search(rf'(\w+ \d+ \d+:\d+:\d+) .*SRC=(.*?) DST=(.*?) .*SPT=(.*?) DPT={port}', line)
            if match:
                date_time = match.group(1).split()
                date = date_time[0]
                time = date_time[1]
                src_ip = match.group(2)
                dst_ip = match.group(3)
                src_port = match.group(4)

                writer.writerow({
                    'Date': date,
                    'Time': time,
                    'Source IP': src_ip,
                    'Destination IP': dst_ip,
                    'Source Port': src_port,
                    'Destination Port': port
                })

def generate_invalid_user_report(log_file):
    report_file = "invalid_users.csv"

    with open(log_file, 'r') as file, open(report_file, 'w', newline='') as csvfile:
        fieldnames = ['Date', 'Time', 'Username', 'IP Address']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for line in file:
            match = re.search(r'(\w+ \d+ \d+:\d+:\d+) .*Invalid user (.*?) from (.*?) ', line)
            if match:
                date_time = match.group(1).split()
                date = date_time[0]
                time = date_time[1]
                username = match.group(2)
                ip_address = match.group(3)

                writer.writerow({
                    'Date': date,
                    'Time': time,
                    'Username': username,
                    'IP Address': ip_address
                })

def generate_source_ip_log(log_file, source_ip):
    log_file_name = f"source_ip_{source_ip.replace('.', '_')}.log"

    with open(log_file, 'r') as file, open(log_file_name, 'w') as logfile:
        for line in file:
            if f"SRC={source_ip}" in line:
                logfile.write(line)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python lab4_script_template.py <log_file_path>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    main(log_file_path)
