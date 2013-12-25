#!/usr/bin/env python

# Script to parse Apache log file format for quick trouble shooting
# Using this we can get the most common ip, url, httpcode and agent
# Running this in cron will help to figure out any unusual occurrences in log file
# You can duplicate this script's work using cut, awk, sort, uniq
# Written on 10/9/2013 by Syed Ali syed_a_ali@yahoo.com


import argparse
import re
from collections import defaultdict
import pdb

def check_args():
    """ Ensures that we have the proper arguments to program """
    parser = argparse.ArgumentParser(
        description="Apache Log File Grep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        version='0.1',
        epilog='''
        Examples:
        apacher -n 10 -l <apache_access_log_filename> -s ip (top 10 incoming connections)
        apacher -n 10 -l <apache_access_log_filename> -s url (top 10 urls requested)
        apacher -n 10 -l <apache_access_log_filename> -s httpcode (top 10 http codes)
        apacher -n 10 -l <apache_access_log_filename> -s agent (top 10 browsers)
        apacher -n 10 -l <apache_access_log_filename> -s all (top 10 of the above)
        '''
    )

    parser.add_argument("-n", action="store", help="number of records to return", type=int)
    parser.add_argument("-l", action="store", help="log file name to analyze")
    parser.add_argument("-s", action="store", help="ip/urls/time/httpcode/agent/all")
    args = parser.parse_args()

    return args

def print_dict(pattern_dict,display,msg):
    """ Handles printing of the output """

    # Here we are printing whatever msg we have been given
    counter = -1
    print "*" *20, msg, "*" *20
    if display == 0:
        # Using lambda to sort on values instead of keys
        for key, value in sorted(pattern_dict.iteritems(), key = lambda x: x[1], reverse=True):
            print("%s: %s" % (key, value))
    else:
        for key, value in sorted(pattern_dict.iteritems(), key = lambda x: x[1], reverse=True):
            if counter == display - 1 :
                break
            else:
                print("%s: %s" % (key, value))
                counter += 1

def process_log_file(args):
    """ Process the log file """

    # Compiles the Apache log file format, which is similar to the example below
    # 192.168.122.3 - - [06/Oct/2013:03:21:38 -0700] "GET / HTTP/1.0" 302 276 "-" "check_http/v1.4.16 (nagios-plugins 1.4.16)"
    pattern = re.compile(r"""(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+
                    (?P<ident>\-)\s+                    # assuming always to be -
                    (?P<username>\-)\s+                 # assuming always to be -
                    (?P<timezone>\[(.*?)\]|-)\s+        # Ex: [29/Sep/2013:03:52:33 -0700] or -
                    (?P<url>\"(.*?)\"|-)\s+             # Ex: "GET / HTTP/1.0" or -
                    (?P<httpcode>\d{3}|-)\s+            # Ex: 200 or -
                    (?P<size>\d+|-)\s+                  # Ex:512 or -
                    (?P<referrer>\".*?\"|-)\s+        # Ex:"http://www.google.com" or -
                    (?P<agent>\".*?\"|-)""", re.VERBOSE)# Ex: "Mozilla/5.0 Galeon/1.0.2 (X11; Linux i686; U;)" or -

    dict_ip = defaultdict(int)
    dict_url = defaultdict(int)
    dict_httpcode = defaultdict(int)
    dict_agent = defaultdict(int)

    # If we are not asked to print 'n' number of lines, print all of them
    if args.n:
        display = args.n
    else:
        display = 0

    msg = { 'ip':'Top Source IP',
            'url': 'Top destination URL',
            'httpcode': 'Top HTTP codes',
            'agent': 'Top HTTP agents'}

    # Skip ::1 loopback which Apache uses to check on it's children
    #::1 - - [22/Dec/2013:04:02:03 +0000] "OPTIONS * HTTP/1.0" 502 484 "-" "Apache/2.2.3 (CentOS) (internal dummy connection)"
    loopback = re.compile('^::1\s+.*',re.VERBOSE)
    
    # Create dictionary for each of the values, and only print the ones being asked to
    with open(args.l, "r") as file:
        for line in file:
            line.strip("\n")
            if re.match(loopback,line):
                continue
            match = re.search(pattern,line)
            dict_ip[match.group('ip')] += 1
            dict_url[match.group('url')] += 1
            dict_httpcode[match.group('httpcode')] += 1
            dict_agent[match.group('agent')] += 1

        if args.s == 'ip':
            print_dict(dict_ip,display,msg['ip'])
        if args.s == 'url':
            print_dict(dict_url,display,msg['url'])
        if args.s == 'httpcode':
            print_dict(dict_httpcode,display,msg['httpcode'])
        if args.s == 'agent':
            print_dict(dict_agent,display,msg['agent'])
        if args.s == 'all':
            print_dict(dict_ip,display,msg['ip'])
            print_dict(dict_url,display,msg['url'])
            print_dict(dict_httpcode,display,msg['httpcode'])
            print_dict(dict_agent,display,msg['agent'])

def main():
    """ Start of program logic """
    args = check_args()
    process_log_file(args)


if __name__ == '__main__':
    main()
