                                                  README
#############################################################################################################

I. GOAL

  Determine the top 10 most common source IP addresses, and their hit rates, for a fleet of 1000 web servers 
  within the last hour.
  
  The following assumptions may be used...
  * web servers are locally writing access logs in the Apache Combined Log Format 
    (http://httpd.apache.org/docs/current/logs.html#combined).
  * web servers are accessible by ssh.

II. USAGE

  Run the program with the following general usage:

    Syntax: find_common_ips.py < path to server list file > [options]
  
    positional arguments:
      server_list		Path to the text file containing list of servers

    optional arguments:
      -h, --help		show this help message and exit
      -N N		Outputs N number of most common IP Addresses (Default: 10)
      -L LOGPATH, --logpath LOGPATH
      			Change the log file location on server, common for all
      			(Default: /var/log/httpd-access-log)
      -T TIMEDIFF, --timediff TIMEDIFF
      			Change the time difference when looking for common
      			IPs, in hours (Default: 1 hour)
                          
III. DEPENDENCIES

  The program needs the following dependencies to function properly:

  - Python3+: The program is written in Python3.4
  - paramiko: To connect to the servers via SSH connection (https://github.com/paramiko/paramiko/)
  - dateutil: To parse the date and time from the logs (http://labix.org/python-dateutil)
  - pytz: To get the UTC timezone for every time conversion (http://pytz.sourceforge.net/)
  - server_list.txt: A text file with server info in it. The format for the server list is as follows:
	* All servers listed in separate line
 	* At every line, the format to add a new server is: <Server's IP-Address> <Username> <Password>
	* The file should be readable with proper permissions
  - The SSH connection needs only IP addresses of the servers instead of hostname. The commented code
    can be uncommented after adding a valid host key, and this will allow the code to accept hostnames.

IV. SOLUTION

  * The program opens the server_list text file and operates on one server at a time (can be multi-threaded).
  It connects to the server via SSH and reads the contents of the log file that is saved locally on the 
  server. 
  
  * It parses the log file, one line at a time, and returns information like IP Address, Time, and Status
  Code. It checks the timestamp and moves ahead only if the time difference is acceptable (default 1 hour).
  
  * After finishing looking up log files on all the servers (can be more than 1000), it sorts the IPs that were
  stored in a dictionary with their counts. The last element has the highest occurrence.

  * It then prints the IPs and their hit rates before exiting.


