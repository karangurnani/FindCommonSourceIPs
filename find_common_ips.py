#! /usr/bin/env python
"""
Determines the top 10 most common source IP addresses, and their hit rates,
for a fleet of 1000 web servers within the last hour

Syntax: find_common_ips <path to server list file> [options]

positional arguments:
  server_list           Path to the text file containing list of servers

optional arguments:
  -h, --help            show this help message and exit
  -N N                  Outputs N number of most common IP Addresses (Default:
                        10
  -L LOGPATH, --logpath LOGPATH
                        Change the log file location on server, common for all
                        (Default: /var/log/httpd-access-log)
  -T TIMEDIFF, --timediff TIMEDIFF
                        Change the time difference when looking for common
                        IPs, in hours (Default: 1 hour)
"""


import os
import sys
import re
import paramiko
import collections
import operator
import datetime
import dateutil.parser
import pytz
#import base64  # for generating RSA keys (Skipped)
import argparse


def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description='Determines the top 10 most common source IP addresses, and their hit'
                                                 ' rates, for a fleet of 1000 web servers within the last hour')
    parser.add_argument('server_list', help='Path to the text file containing list of servers')
    parser.add_argument('-N', default=10, type=int,
                        help='Outputs N number of most common IP Addresses (Default: 10')
    parser.add_argument('-L', '--logpath', default='/var/log/httpd-access-log', type=str,
                        help='Change the log file location on server, common for all '
                             '(Default: /var/log/httpd-access-log)')
    parser.add_argument('-T', '--timediff', default=1, type=int,
                        help='Change the time difference when looking for common IPs, in hours (Default: 1 hour)')
    args = parser.parse_args()

    # Makes sure the server list file is valid
    check_path(args.server_list, parser)

    # Dictionaries for IP Address and Hit counts
    ip_dict = collections.defaultdict(int)
    hit_success = collections.defaultdict(int)

    with open(args.server_list, "rb") as servers:
        for server in servers:
            # The program expects a valid format for listing servers
            hostname, user, passwd = server.split()
            # Generate RSA key for host key verification (Skipped)
            #key = paramiko.RSAKey(data=base64.decodestring('AAA...'))  # needs host key
            # Starts the SSH Client
            client = paramiko.SSHClient()
            # Add the host to known hosts by adding the RSA key (Skipped)
            #client.get_host_keys().add('ssh.example.com', 'ssh-rsa', key)
            # Ignores the warnings for RSA Keys
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Connects to the server
            client.connect(hostname.decode('UTF-8'),
                           username=user.decode('UTF-8'), password=passwd.decode('UTF-8'))
            # Copies the log file data to a variable
            _, data, _ = client.exec_command("cat {}".format(args.logpath))
            log_data = []
            # Stores the log data in a list
            for line in data:
                log_data.append(line.strip("\n"))

            # Parses each log data and stores the IP address and hit counts at each step
            for log in log_data:
                ip_address, date_time, status_code = parse_log(log)
                if check_time(date_time, args.timediff):
                    ip_dict[ip_address] += 1
                    if status_code == "200":
                        hit_success[ip_address] += 1
                else:
                    break

    # An ascending list of IP address occurrences
    ip_list = sorted(list(ip_dict.items()), key=operator.itemgetter(1))

    if ip_list:
        print("IP Address      Hit Rate")
        for _ in range(args.N):
            # Gets the last element that has the highest occurrence
            try:
                top_ip, total_hits = ip_list.pop()
            except IndexError:
                break
            # Hit Rate = # of successful connections/total connection attempts
            hit_rate = (hit_success[top_ip]/total_hits)*100

            print("{0} ---- {1:.2f}%".format(top_ip, hit_rate))
    else:
        print("No results found.")

    parser.exit(0)
#end main


def check_time(log_time, offset):
    """Checks if timestamp is not older than a given limit"""
    log_time = list(log_time)
    # Remove unnecessary colon
    log_time[11] = " "
    log_time = ''.join(log_time)
    # Convert the time in UTC
    dt_log = dateutil.parser.parse(log_time)
    dt_log = dt_log.astimezone(pytz.UTC)
    # Convert current time in UTC
    dt_utc = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
    # Roll back current time by X hours defined by offset
    dt_utc = dt_utc - datetime.timedelta(hours=offset)

    # Compare both times
    if dt_log >= dt_utc:
        return True
    else:
        return False
#end check_time


def parse_log(log_data):
    """Parses the Apache log file and returns relevant details"""
    # Apache log format regex
    format_pat = re.compile(
        r"(?P<host>[\d\.]+)\s"
        r"(?P<identity>\S*)\s"
        r"(?P<user>\S*)\s"
        r"\[(?P<time>.*?)\]\s"
        r'"(?P<request>.*?)"\s'
        r"(?P<status>\d+)\s"
        r"(?P<bytes>\S*)\s"
        r'"(?P<referer>.*?)"\s'
        r'"(?P<user_agent>.*?)"\s*'
    )
    match = format_pat.match(log_data)
    # Create a dict out of the parsed data
    info = match.groupdict()
    ip_address = info.pop('host', None)
    date_time = info.pop('time', None)
    status_code = info.pop('status', None)
    # Return IP, time and status code only
    return ip_address, date_time, status_code
#end parse_log


def check_path(path, parser):
    """Checks the file path existence, type and permissions"""
    if not os.path.exists(path):
        print("File does not exist:\n%s", path)
        parser.exit(1)
    if not os.path.isfile(path):
        print("File is a directory:\n%s", path)
        parser.exit(1)
    if not os.access(path, os.R_OK):
        print("File does not have read permissions:\n%s", path)
        parser.exit(1)
#end check_path


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("KeyboardInterrupt: Program execution stopped unexpectedly.")
    except Exception as e:
        print("RUNTIME ERROR: "+str(e))
        sys.exit(1)
#end __main__