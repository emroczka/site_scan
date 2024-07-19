#
# Created by: Eric Mroczka
# Current version 3.5
# Date: 2024.07.16
#       - fixed missing target IP address in command log output from crypto testing function
#		- moved testssl.sh (scan6) back to top of crypto testing function
#       - removed unnecessary variable from remove_excluded_targets function
#       - Added output files to command log
#       - Added global User-Agent string variable
#       - fixed testssl.sh existing output file check (to skip a re-run of that scan)
#       - Added nuclei metrics monitoring comment
#       - FUTURE ITEM: Dictionary of other programs needed and their installation locations (i.e. ag,
#            testssh.sh, etc)
#       - FUTURE ITEM: Log creation and addition to secondary scan files (i.e. scan5_all_http_ports)
#            in command log
#       - FUTURE ITEM: fix eyewitness target file going to command log (i.e. contents on
#            scan5_all_http_ports)
#
# Version History:
# ----------------
# version 3.4
# Date: 2024.07.15
#       - Added notes on timezones
#		- Modified LOG_FILE to include site_id in name
#       - fixed print output format command in crypto testing function
#       - fixed print output format command in ssh testing function
#       - fixed data_dir in testssl.sh command
#
# version 3.3
# Date: 2024.07.14
#       - Added log_command calls to initial setup functions.
#		- Moved generation of target files from the nMap scans to a separate function call.
#       - Removed filter for tcp/9700 from create_target_lists function, creating ssl ports list
#
# version 3.2
# Date: 2024.07.14
#       - Added setup function so that the individually called functions could actually run.
#		- Removed pre-v3.0 history
#
# version 3.1
# Date: 2024.07.14
#       - Automatically add local IP Addresses to exclusions.txt
#
# version 3.0
# Date: 2024.07.12
#       - Added functionality to allow most individual function executions from the command line
#       - Added more comments in run_crypto_checks function
#       - Added target_ip to command log output
#       - Added function to get the local system IP Address
#       - Added source_ip to command log output
#

import os
import time
import subprocess
import csv
from pathlib import Path
from datetime import datetime
import pytz
import sys
import socket

#
# TIMEZONES can be found using python loop:
# import pytz
# 
# for tz in pytz.all_timezones:
#    print tz
#
# Common options: UTC, Etc/GMT-5
#

TIMEZONE = 'UTC'
USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'

def get_local_ip():
    """
    Parameters:
        None
            
    Returns:
        Local system IP address
        
    Description:
        This function creates a UDP socket and connects it to Google's public DNS server (8.8.8.8). It then retrieves
        the local IP address assigned to the socket, which will not be the loopback address (127.0.0.1). The
        connection to the remote address does not need to be successful; it only needs to be attempted for the local
        IP address to be determined. Finally, it closes the socket.
     """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Connect to a remote address (doesn't need to be reachable)
        sock.connect(("8.8.8.8", 0))
        
        # Get the local address
        local_ip = sock.getsockname()[0]
    except Exception as e:
        local_ip = None
    finally:
        # Close the socket
        sock.close()
    
    return local_ip

def add_exclusion(IPAddress, output_dir):
    """
    Parameters:
        IPAddress : str
            Local IP Address to add to exclusions.txt file
        output_dir : str
            The base directory where the site_id subdirectory was created
        
    Returns:
        Nothing
        
    Description:
        This function takes the provided IP Address and appends it to the Exclusions.txt file in the provided directory.
     """
    print("Adding local IP Address to exclusions.txt")
    exclusions_path = f"{output_dir}/exclusions.txt"
    with open(exclusions_path, 'a') as excl:
        excl.write(IPAddress + "\n")

def log_command(log_file, command, source_ip, target_ip, scan_output_file, comment):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        command : str
            The command that was executed
        source_ip : str
            Source IP address scan is coming from. Placed into command log.
        target_ip : str
            Target IP address scan is coming from. Placed into command log.
        scan_output_file : str
            Output file from scan to be written to the command log.
        comment : str
            A brief comment on what the command being executed is doing
            
    Returns:
        nothing
        
    Description:
        This function logs the execution of a command with a timestamp to a CSV file.
    """
    timestamp = datetime.now(pytz.timezone(TIMEZONE)).strftime('%m/%d/%Y %H:%M:%S')
    log_entry = [timestamp, TIMEZONE, comment, source_ip, target_ip, scan_output_file, command]
    
    with open(log_file, 'a', newline='') as csvfile:
        log_writer = csv.writer(csvfile)
        log_writer.writerow(log_entry)

def run_command(log_file, command, source_ip, target_ip, scan_output_file, comment):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        command : str
            The command to be executed
        source_ip : str
            Source IP address scan is coming from. Placed into command log.
        target_ip : str
            Target IP address scan is coming from. Placed into command log.
        scan_output_file : str
            Output file from scan to be written to the command log.
        comment : str
            A brief comment on what the command is doing
            
    Returns:
        int
            The return code of the command
        
    Description:
        This function accepts a command and executes it,
        displaying its output in real-time and logging the execution.
    """
    log_command(log_file, command, source_ip, target_ip, scan_output_file, comment)
    process = subprocess.Popen(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    rc = process.poll()
    return rc

def create_directory(log_file, site_id, dir_to_make):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        site_id : str
            The Site ID that will be created under the output_dir folder to store test results
        output_dir : str
            The base directory where the site_id subdirectory is to be created
            
    Returns:
        nothing
        
    Description:
        This function creates a directory if it does not already exist.
    """
    if os.path.exists(dir_to_make):
        print(" Skipping creation of Site ID folder as it already exists.")
    else:
        print(f" Creating directory for output - {dir_to_make}")
        os.makedirs(dir_to_make, exist_ok=True)
        log_command(log_file, f"mkdir {dir_to_make}", "", "", dir_to_make, f"Making folder for Site ID {site_id}")


def write_range_file(log_file, data_dir, cidr_range):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        data_dir : str
            The directory where the range.txt file will be written
        cidr_range : str
            The CIDR range to be written to the file
            
    Returns:
        nothing
        
    Description:
        This function writes the given CIDR range to a file named range.txt
        in the specified directory if it does not already exist.
    """
    range_file = data_dir + "/range.txt"
    if os.path.exists(range_file):
        print("  Skipping creation of range.txt as it already exists.")
    else:
        print("  Writing out range.txt...")
        log_command(log_file, f"Placing CIDR range {cidr_range} into range.txt", "", "", range_file, "Saving provided CIDR_Range to file.")
        with open(range_file, 'w') as f:
            f.write(cidr_range)

def create_list_of_hosts(log_file, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        data_dir : str
            The directory containing the range.txt file
            
    Returns:
        nothing
        
    Description:
        This function generates a list of living hosts from CIDR ranges specified in range.txt and
        writes the results to fping-sweep.txt. It only does this if the file fping-sweep.txt does
        not exist.
    """
    ping_sweep_file = data_dir + "/fping-sweep.txt"
    if os.path.exists(ping_sweep_file):
        print("    Skipping creation of fping-sweep.txt as it already exists.")
    else:
        print("    Creating list of hosts...")
        with open(f"{data_dir}/range.txt", 'r') as f:
            cidr_ranges = f.readlines()
        log_command(log_file, f"fping -g {cidr_ranges}", "", "", ping_sweep_file, "Running ping-sweep against CIDR range")
        with open(ping_sweep_file, 'w') as f:
            for cidr in cidr_ranges:
                result = subprocess.run(f"fping -g {cidr.strip()}", shell=True, text=True, capture_output=True)
                f.write(result.stdout)

def trim_active_targets(log_file, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        data_dir : str
            The directory containing the fping-sweep.txt and targets.txt files
            
    Returns:
        nothing
        
    Description:
        This function trims the list of living hosts to include only active
        targets and writes them to targets.txt.
    """
    ping_sweep_file = data_dir + "/fping-sweep.txt"
    targets_file = data_dir + "/targets.txt"
    if os.path.exists(targets_file):
        print("      Skipping the trimming list down function as the trimmed target list already exists.")
    else:
        print("      Trimming list down to active targets...")
        log_command(log_file, "Filtering live hosts from fping-sweep.txt to targets.txt", "", "", targets_file, "Creating trimmed down list of targets")
        with open(ping_sweep_file, 'r') as f:
            lines = f.readlines()
        with open(targets_file, 'w') as f:
            for line in lines:
                if "alive" in line:
                    f.write(line.split()[0] + "\n")

def remove_excluded_targets(log_file, full_output_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        full_output_dir : str
            The directory containing the targets.txt & exclusions.txt files
            
    Returns:
        nothing
        
    Description:
        This function removes targets listed in exclusions.txt from the
        targets.txt file.
    """
    exclusions_path = f"{full_output_dir}/exclusions.txt"
    targets_file = full_output_dir + "/targets.txt"
    if not os.path.exists(exclusions_path):
        print(f"        No exclusions.txt file found at {exclusions_path}. Skipping exclusions.")
    else:
        print("        Exclusions.txt found...removing exclusions from targets list now...")
        log_command(log_file, "Filtering exclusions from targets.txt", "", "", targets_file, "Applying exclusions list to targets list")    
        with open(exclusions_path, 'r') as f:
            exclusions = {line.strip() for line in f}

        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f]

        with open(targets_file, 'w') as f:
            for target in targets:
                if target not in exclusions:
                    f.write(target + "\n")

def create_target_lists(data_dir, target):
    """
    Parameters:
        data_dir : str
            The directory containing the nMap output files
        target : str
            Target IP address scan is running against.
            
    Returns:
        nothing
        
    Description:
        This function takes the output from Nmap scans and places identified and filtered targets into different
        files for other scans (http, ssl, ssh) to use.
    """
    print(f"    Building a list of http ports for host {target}...")
    http_ports = subprocess.run(f"ag http {data_dir}/scan4_tcp_version_scan_{target}.nmap | ag open | cut -d ':' -f 2 | cut -d '/' -f 1", shell=True, text=True, capture_output=True).stdout
    with open(f"{data_dir}/scan5_http_tcp_ports_{target}", 'w') as f:
        f.write(http_ports)

    if os.path.getsize(f"{data_dir}/scan5_http_tcp_ports_{target}") > 0:
        with open(f"{data_dir}/scan5_http_tcp_ports_{target}", 'r') as f:
            with open(f"{data_dir}/scan5_all_http_ports", 'a') as all_http:
                for line in f:
                    all_http.write(f"{target}:{line.strip()}\n")

    print(f"    Building a list of ssl ports for host {target}...")
    ssl_ports_result = subprocess.run(f"ag ssl {data_dir}/scan4_tcp_version_scan_{target}.nmap | cut -d ':' -f 2 | cut -d '/' -f 1 | grep -v 'SF'", shell=True, text=True, capture_output=True)
    ssl_ports = ssl_ports_result.stdout.strip()
    with open(f"{data_dir}/scan6_crypto_ports_{target}", 'w') as f:
        f.write(ssl_ports)

    with open(f"{data_dir}/scan6_crypto_ports_{target}", 'r') as f:
        with open(f"{data_dir}/scan6_all_crypto_ports", 'a') as all_crypto:
            for line in f:
                all_crypto.write(f"{target}:{line.strip()}\n")
            
    print(f"    Building a list of ssh ports for host {target}...")
    ssh_ports = subprocess.run(f"ag ssh {data_dir}/scan4_tcp_version_scan_{target}.nmap | ag open | cut -d ':' -f 2 | cut -d '/' -f 1", shell=True, text=True, capture_output=True).stdout
    with open(f"{data_dir}/scan12_ssh_ports_{target}", 'w') as f:
        f.write(ssh_ports)

    with open(f"{data_dir}/scan12_ssh_ports_{target}", 'r') as f:
        with open(f"{data_dir}/scan12_all_ssh_ports", 'a') as all_ssh:
            for line in f:
                all_ssh.write(f"{target}:{line.strip()}\n")

def run_nmap_scans(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory containing the targets.txt file and where the scan output files should be saved.
            
    Returns:
        nothing
        
    Description:
        This function runs various Nmap scans on the targets listed in
        targets.txt and writes the results to files in the specified directory.
    """
    targets_file = data_dir + "/targets.txt"
    if not os.path.exists(targets_file):
        print("  No targets.txt file found. Aborting nMap scans.")
    else:
        with open(targets_file, 'r') as f:
            targets = f.readlines()

        print("OK, here we go. Beginning Nmap scans of individual targets...")
        for target in targets:
            target = target.strip()
            print(f"***Full TCP scan of {target}...")
            run_command(log_file, f"nmap -sT -Pn -n -p- -vvv --stats-every 5 -T4 {target} -oA {data_dir}/scan2_Full-TCP_scan_{target}", source, target, f"{data_dir}/scan2_Full-TCP_scan_{target}", "Full TCP Scan")
            print(f"***Top 1000 UDP scan of {target}...")
            run_command(log_file, f"sudo nmap -sU -Pn -n -vvv --stats-every 5 -T4 {target} -oA {data_dir}/scan3_T1000-UDP_scan_{target}", source, target, f"{data_dir}/scan3_T1000-UDP_scan_{target}", "Top 1000 UDP Scan")
    
            print(f"    Parsing and writing open ports to file...")
            tcp_ports = subprocess.run(f"ag open {data_dir}/scan2_Full-TCP_scan_{target}.nmap | cut -d ':' -f 2 | cut -d '/' -f 1", shell=True, text=True, capture_output=True).stdout
            with open(f"{data_dir}/scan4_open_tcp_ports_{target}", 'w') as f:
                f.write(tcp_ports)
            
            udp_ports = subprocess.run(f"ag 'open ' {data_dir}/scan3_T1000-UDP_scan_{target}.nmap | cut -d ':' -f 2 | cut -d '/' -f 1", shell=True, text=True, capture_output=True).stdout
            with open(f"{data_dir}/scan4_open_udp_ports_{target}", 'w') as f:
                f.write(udp_ports)
    
            if os.path.getsize(f"{data_dir}/scan4_open_tcp_ports_{target}") > 0:
                print(f"***   Running TCP Version scan...")
                run_command(log_file, f"sudo nmap -sV -Pn -n --stats-every 5 -p $(tr '\\n' , <{data_dir}/scan4_open_tcp_ports_{target}) -vvv {target} -oA {data_dir}/scan4_tcp_version_scan_{target}", source, target, f"{data_dir}/scan4_tcp_version_scan_{target}", "TCP Version Scan")
    
            if os.path.getsize(f"{data_dir}/scan4_open_udp_ports_{target}") > 0:
                print(f"***   Running UDP Version scan...")
                run_command(log_file, f"sudo nmap -sVU -Pn -n --stats-every 5 -p $(tr '\\n' , <{data_dir}/scan4_open_udp_ports_{target}) -vvv {target} -oA {data_dir}/scan4_udp_version_scan_{target}", source, target, f"{data_dir}/scan4_udp_version_scan_{target}", "UDP Version Scan")
            
            create_target_lists(data_dir, target)

        print("Individual, targeted NMap scans complete.")

def check_nmap_scans(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory containing the targets.txt file
            
    Returns:
        nothing
        
    Description:
        This verifies that we are set to run nMap scans. And if ready, calls the function
        to actually run the scans.
    """
    targets_file = data_dir + "/targets.txt"
    if not os.path.exists(targets_file):
        print("  No targets.txt file found. Aborting nMap scans.")
    else:
        run_nmap_scans(log_file, source, data_dir)

def run_eyewitness(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory containing the scan5_all_http_ports file and where the scan
            output files should be saved.
            
    Returns:
        nothing
        
    Description:
        This function runs Eyewitness against select targets specified
        in scan5_all_http_ports.
    """
    http_file = data_dir + "/scan5_all_http_ports"
    if not os.path.exists(http_file):
        print("        No http targets file available for perform scans. Aborting...")
    else:
        if os.path.getsize(http_file) > 0:
            print("***Running Eyewitness against select targets - IPs & Ports...")
            run_command(log_file, f"/home/vagrant/git-repos/eyewitness/Python/EyeWitness.py -f {data_dir}/scan5_all_http_ports --web --timeout 60 --no-prompt --user-agent '{USER_AGENT}' -d {data_dir}/scan4_eyewitness-report", source, "Contents of scan5_all_http_ports", f"{data_dir}/scan4_eyewitness-report", "Running Eyewitness against select targets - IPs & Ports")
            print("  Eyewitness run complete.")
        else:
            print("Skipping Eyewitness due to empty http targets file.")
           
def run_crypto_checks(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory containing the scan6_all_crypto_ports file and where the scan output files should be saved.
            
    Returns:
        nothing
        
    Description:
        This function performs crypto scans using various tools on ports
        specified in scan6_all_crypto_ports.
    """
    crypto_file = data_dir + "/scan6_all_crypto_ports"
    if not os.path.exists(crypto_file):
        print("        No crypto file available for perform scans. Aborting...")
    else:
        if os.path.getsize(crypto_file) > 0:
            print("***Starting Crypto scans...")
            print("        File with Crypto targets found...")    
            print("***Beginning TestSSL scans of individual targets...")
            print("   ***testssl.sh...")
            with open(crypto_file, 'r') as f:
                for line in f:
                    target, port = line.strip().split(':')
                    test_output_file = f"{data_dir}/scan6_testssl.sh-{target}_{port}.txt"
                    if os.path.exists(test_output_file):
                        print(f"Skipping TestSSL scan for {target}:{port} as output file already exists.")
                        continue
                    print(f"  Running TestSSL scan of {target}:{port}...")    
                    run_command(log_file, f"/home/vagrant/git-repos/testssl.sh/testssl.sh --hints --warnings batch --logfile {data_dir}/scan6_testssl.sh-{target}_{port}.txt https://{line.strip()}", source, f"{target}:{port}", f"{data_dir}/scan6_testssl.sh-{target}_{port}.txt", "Running testssl.sh against target")

            print("   ***nMap scripts...")
            with open(crypto_file, 'r') as f:
                for line in f:
                    target, port = line.strip().split(':')
                    test_output_file = f"{data_dir}/scan7_nmap_ssl-cert_ssl-enum-ciphers_{target}-{port}.nmap"
                    if os.path.exists(test_output_file):
                        print(f"Skipping nMap Crypto scan for {target}:{port} as output file already exists.")
                        continue
                    print(f"  Running nMap Crypto scan of {target}:{port}...")
                    run_command(log_file, f"nmap -sT -Pn -n -p {port} '--script=+http* and not (brute or dos or external)' --script=ssl-cert,ssl-enum-ciphers -vv --stats-every 15 -oA {data_dir}/scan7_nmap_ssl-cert_ssl-enum-ciphers_{target}-{port} {target}", source, f"{target}:{port}", f"{data_dir}/scan7_nmap_ssl-cert_ssl-enum-ciphers_{target}-{port}", "Running nMap Crypto scan")

            print("   ***sslscan...")
            with open(crypto_file, 'r') as f:
                for line in f:
                    target, port = line.strip().split(':')
                    test_output_file = f"{data_dir}/scan8_sslscan-{target}_{port}.txt"
                    if os.path.exists(test_output_file):
                        print(f"Skipping sslscan for {target}:{port} as output file already exists.")
                        continue
                    print(f"  Running sslscan of {target}:{port}...")
                    run_command(log_file, f"sudo /usr/bin/sslscan --verbose --show-certificate {line.strip()} > {data_dir}/scan8_sslscan-{target}_{port}.txt", source, f"{target}:{port}", f"{data_dir}/scan8_sslscan-{target}_{port}.txt", "Running sslscan against target")
        else:
            print("        File with Crypto targets is empty. Aborting crypto scans...")                

def run_nuclei_scans(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory containing the scan5_all_http_ports file and where the scan output files should be saved.
            
    Returns:
        nothing
        
    Description:
        This function performs nuclei scans on HTTP ports specified in
        scan5_all_http_ports.
    
    Nuclei CLI options used:
        -duc = disable update checks
        -v = show verbose output
        -ts = enables printing timestamp in cli output
        -sresp = store all request/response passed through nuclei to output directory
        -srd = directory to store the request/responses in
        -w = workflow to run
        -H = custom header/cookie to include in all http request in header:value format (cli, file)
             I use this to specify the User-Agent string to use.
        -ni = Disabled use of interactsh server (oast)
        
    Nuclei metrics are enabled by default. Use this command to monitor the scan:
        watch -t -n5 "curl -s http://localhost:9092/metrics | jq"
    """
    http_file = data_dir + "/scan5_all_http_ports"
    if not os.path.exists(http_file):
        print("        No http targets file available for perform scans. Aborting...")
    else:
        if os.path.getsize(http_file) > 0:
            print("        File with Http targets found...")    
            print("***Starting nuclei scans...")
            with open(http_file, 'r') as f:
                for line in f:
                    target, port = line.strip().split(':')
                    run_command(log_file, f"/usr/bin/nuclei -duc -v -ts -ni -w workflows/verifone-workflow.yaml -o {data_dir}/scan9_nuclei-Verifone-{target}_{port}.txt -sresp -srd {data_dir}/scan9_nuclei-Verifone-{target}_{port}/ -H User-Agent:'{USER_AGENT}' -u {line}", source, f"{target}:{port}", f"{data_dir}/scan9_nuclei-Verifone-{target}_{port}/", "Running nuclei with verifone workflow")
        else:
            print("        File with Http targets is empty. Skipping Nuclei scans.")

def run_ipv6_ping(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory where scan10-IPv6_ping_sweep and scan11-MAC_Addresses files will be written
            
    Returns:
        nothing
        
    Description:
        This function performs IPv6 ping sweep and retrieves MAC addresses.
    """
    print("***Running IPv6 ping sweep")
    run_command(log_file, "ping6 -c 5 ff02::1%eth0 > /dev/null", source, "All IPv6 Multicast nodes", "", "Send an ICMPv6 echo request (type 128) message to the all-nodes multicast address")
    run_command(log_file, f"ip -6 neigh > {data_dir}/scan10-IPv6_ping_sweep", source, "", f"{data_dir}/scan10-IPv6_ping_sweep", "Dumping the neighbor cache")
    run_command(log_file, f"arp -a > {data_dir}/scan11-MAC_Addresses", source, "", f"{data_dir}/scan11-MAC_Addresses", "Dump arp table for cross-reference")

def run_ssh_scans(log_file, source, data_dir):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        source : str
            Source IP address scan is coming from. Placed into command log.
        data_dir : str
            The directory containing the targets.txt and scan4_tcp_version_scan_* files
            
    Returns:
        nothing
        
    Description:
        This function performs SSH scans on hosts listed in targets.txt
        and writes the results to corresponding files.
    """
    ssh_file = data_dir + "/scan12_all_ssh_ports"
    if not os.path.exists(ssh_file):
        print("        No ssh targets file available for perform scans. Aborting...")
    else:
        if os.path.getsize(ssh_file) > 0:
            print("***Starting ssh scans...")
            with open(ssh_file, 'r') as f:
                for line in f:
                    target, port = line.strip().split(':')
                    test_output_file = f"{data_dir}/scan12_ssh-{target}_{port}.txt"
                    if os.path.exists(test_output_file):
                        print(f"Skipping ssh-audit.py scan for {target}:{port} as output file already exists.")
                        continue
                    print(f"  Running ssh-audit.py scan of {target}:{port}...")    
                    run_command(log_file, f"/home/vagrant/git-repos/ssh-audit/ssh-audit.py -v {target} -p {port} > {data_dir}/scan12_ssh-{target}_{port}.txt", source, f"{target}:{port}", f"{data_dir}/scan12_ssh-{target}_{port}.txt", "Running sshaudit against identified SSH target")
        else:
            print("ssh targets file is empty. Aborting ssh scans.")

def run_setup(log_file, site_id, output_dir, full_output_dir, cidr_range, source):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        site_id : str
            The Site ID that will be created under the output_dir folder to store test results
        output_dir : str
            The base directory where the output folder will be created
        full_output_dir : str
            The complete directory path where the output files will be stored
        cidr_range : str
            The CIDR range to be scanned
        source : str
            Source IP address scan is coming from. Placed into command log.
            
    Returns:
        nothing
        
    Description:
        This function orchestrates the initial items necessary to support scanning activities.
    """
    write_range_file(log_file, full_output_dir, cidr_range)
    create_list_of_hosts(log_file, full_output_dir)
    trim_active_targets(log_file, full_output_dir)
    remove_excluded_targets(log_file, full_output_dir)

def run_full_script(log_file, site_id, output_dir, full_output_dir, cidr_range, source):
    """
    Parameters:
        log_file : str
            The full path and filename to write logs to
        site_id : str
            The Site ID that will be created under the output_dir folder to store test results
        output_dir : str
            The base directory where the output folder will be created
        full_output_dir : str
            The complete directory path where the output files will be stored
        cidr_range : str
            The CIDR range to be scanned
        source : str
            Source IP address scan is coming from. Placed into command log.
            
    Returns:
        nothing
        
    Description:
        This function orchestrates the entire scanning process if the 'full' option is specified, from
        directory creation to running all of scanning functions.
    """
    run_setup(log_file, site_id, output_dir, full_output_dir, cidr_range, source)
    check_nmap_scans(log_file, source, full_output_dir)
    run_eyewitness(log_file, source, full_output_dir)
    run_crypto_checks(log_file, source, full_output_dir)
    run_nuclei_scans(log_file, source, full_output_dir)
    run_ipv6_ping(log_file, source, full_output_dir)
    run_ssh_scans(log_file, source, full_output_dir)

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run network scanning with nMap, SSL, Eyewitness, Nuclei, ssh, and IPv6 scripts.")
    parser.add_argument('function', choices=['full', 'nmap', 'crypto', 'eyewitness', 'nuclei', 'ipv6', 'ssh'],
                        help="Function to execute.")
    parser.add_argument('--site_id', required=True, help="Directory to create for storing site test results.")
    parser.add_argument('--base_output_dir', required=True, help="Base directory where Site ID folder is created for storing output files.")
    parser.add_argument('--cidr_range', required=True, help="CIDR range for scanning.")

    args = parser.parse_args()

    full_output_dir = args.base_output_dir + "/" + args.site_id
    log_file = full_output_dir + '/command_log2-' + args.site_id + '.csv'
#
# We are assuming that the system only has 1 IP Address. No sanity checking is performed
# to verify that the local system IP Address is within the provided CIDR Address range.
#
    IPAddr = get_local_ip()
    print("Local IP Address:", IPAddr)
    create_directory(log_file, args.site_id, full_output_dir)
    add_exclusion(IPAddr, full_output_dir)
    
    if args.function == 'full':
        if not args.cidr_range:
            parser.error("The full run requires --cidr_range, --site_id, and --base_output_dir to be specified.")
        run_full_script(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
    elif args.function == 'nmap':
        run_setup(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
        check_nmap_scans(log_file, IPAddr, full_output_dir)
    elif args.function == 'crypto':
        run_setup(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
        run_crypto_checks(log_file, IPAddr, full_output_dir)
    elif args.function == 'eyewitness':
        run_setup(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
        run_eyewitness(log_file, IPAddr, full_output_dir)
    elif args.function == 'nuclei':
        run_setup(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
        run_nuclei_scans(log_file, IPAddr, full_output_dir)
    elif args.function == 'ipv6':
        run_setup(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
        run_ipv6_ping(log_file, IPAddr, full_output_dir)
    elif args.function == 'ssh':
        run_setup(log_file, args.site_id, args.base_output_dir, full_output_dir, args.cidr_range, IPAddr)
        run_ssh_scans(log_file, IPAddr, full_output_dir)

if __name__ == "__main__":
    main()
