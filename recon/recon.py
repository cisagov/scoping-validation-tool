"""
Scope Validation Tool v1.2.0

Copyright 2022 Scope Validation Tool Contributors, All Rights Reserved

License-Identifier: MIT (SEI)-style

Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

DM22-0416
____________________________________
Examples of how to run:
recon RVA123 verify_ip -i 8.8.8.8
recon RVA123 verify_ip --ip 8.8.8.8
recon RVA123 verify_ip -f ips.txt
recon RVA123 verify_ip --file ips.txt

recon RVA123 verify_domain -d google.com
recon RVA123 verify_domain --domain google.com
recon RVA123 verify_domain -f domains.txt
recon RVA123 verify_domain --file domains.txt

recon RVA123 web_services -f domains.txt
"""
import argparse
import subprocess
import os
import sys

from recon import Whois as who


class Bcolors:
    """ Class that stores colors to be outputted to the terminal."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def create_path(path):
    """ Creates path if path does not exist """
    if not os.path.isdir(path):
        os.makedirs(path)
    return path


def country_message(query, country, message=''):
    """ Message to print out based on query's country origin.
    Query can be an IP or a domain name
    """

    if country is not None:
        if "us" in country and len(country) == 1:  # can assume lowercase  and set() based on Whois class
            print(f"{Bcolors.OKGREEN} {query} location resides in the United States. Country = {country}{Bcolors.ENDC}"
                  f"{message}")

        else:  # another country was found OR the len(set()) returned is > 1 even if one item matched to "us"
            print(f"{Bcolors.FAIL} {query} location resides outside the United States. Country = {country}{Bcolors.ENDC}"
                  f"{message}")
    else:
        print(f"{Bcolors.WARNING} {query} could not determine location. Country extracted is None.{Bcolors.ENDC}\n")


def verify_ip_address(assessment_id, ip=None, file=None):
    """ This function takes in an IP or a file listed with IPs and outputs a file that contains the
        IP, organization, CIDR, city region, country, and custName.

        IF a single IP was entered, then the output will only appear on the terminal

        Output File: recon-output/verify-address-*-Location-Lookups.csv

        Input file: List of ips, where each item is entered line by line with no commas separating them
        Input IP: single ip
    """
    path = create_path("recon-output/verify-address")

    # files to output
    location_file_name = f"{path}/{assessment_id}-Location-Lookups.csv"
    dns_file_name = f"{path}/{assessment_id}-DNS-Lookups.txt" # TODO: Use once fqdn is fixed

    if file:
        file = file.name

        with open(file, "r") as file_to_read:
            for line in file_to_read:
                if line.strip():  # cleaning file of any empty lines
                    extracted_ip = line.strip()
                    whois = who.Whois(whois_query=extracted_ip)

                    if whois.ip_custname:
                        message = f"\n\tIP Organization: {whois.ip_organization}\n" \
                                  f"\tCustName: {whois.ip_custname}\n"
                    else:
                        message = f"\n\tIP Organization: {whois.ip_organization}\n"

                    country_message(query=extracted_ip, country=whois.ip_country, message=message)

                    if os.path.exists(location_file_name) is False:  # set headers
                        with open(location_file_name, "w") as file_to_write:
                            file_to_write.write("ip; cidr; organization; city; region; country; custName\n")

                    with open(location_file_name, "a") as location_file:
                        location_file.writelines(f'{extracted_ip}; {whois.ip_cidr}; {whois.ip_organization}; '
                                                 f'{whois.ip_city}; {whois.ip_region}; {whois.ip_country}; '
                                                 f'{whois.ip_custname} \n')

        print(f'\n{Bcolors.OKBLUE}More information about each IP can be found in: {location_file_name}{Bcolors.ENDC}')

    else:  # assume single IP entered
        ip = ip.strip()
        whois = who.Whois(whois_query=ip)

        if whois.ip_custname:
            message = f"\n\tIP Organization: {whois.ip_organization}\n" \
                      f"\tCustName: {whois.ip_custname}\n"
        else:
            message = f"\n\tIP Organization: {whois.ip_organization}\n"

        country_message(query=ip, country=whois.ip_country, message=message)


def verify_domain_helper(whois=None):
    """ Helper to verify_domain(). This was added to handle domains that point to more than one IP.

    Params:
        whois :: initial Whois() for a single domain

    Return:
        whois_ip_dict :: A dictionary that holds all the IPs and their corresponding whois information. Key = IP,
                        value == Whois()
        ip_country_set :: A set with all of the domain's associated IPs countries
        whois_info_message :: a formatted string that will contain selected whois information about every IP found.
                                Info includes: domain organisation, IP(s), IP country(s), IP organization
    """

    whois_ip_dict = dict()  # dictionary to collect my whois info for all ips
    ip_country_set = set()  # Some IPs may be from a different country, so we collect them here
    ips_set = whois.ips_set  # all my ips found for the given domain

    whois_info_message = f"\n\tDomain Organisation: {whois.organisation}\n\tIP: {whois.ip}\n" \
                        f"\t\tIP Organization: {whois.ip_organization}\n\t\tIP Country: {whois.ip_country}\n"

    if ips_set:  # if the domain points to more than one IP
        for ip in ips_set:
            if ip != whois.ip:  # we do not want to waste time querying on the same IP already stored in the backend

                whois_ip = who.Whois(whois_query=ip)
                whois_ip_dict[ip] = whois_ip  # for every additional IP, key == IP and value == whois object

                if whois_ip.ip_country:
                    ip_country_set.union(whois_ip.ip_country)
                if whois_ip.ip_custname:
                    whois_info_message += f"\tIP: {ip}\n\t\tIP Organization: {whois_ip.ip_organization}\n" \
                                          f"\t\tIP Country: {whois_ip.ip_country}\n" \
                                          f"\t\tCustName: {whois_ip.ip_custname}\n"
                else:
                    whois_info_message += f"\tIP: {ip}\n\t\tIP Organization: {whois_ip.ip_organization}\n" \
                                         f"\t\tIP Country: {whois_ip.ip_country}\n"

        return whois_ip_dict, ip_country_set, whois_info_message
    return None, ip_country_set, whois_info_message


def join_ips_country(ip_country_set, first_connected_country):
    """ This is to be used for country message. If there are > 1 IPs then join countries found, else do not join

    Params:
        first_connected_country :: The IP's country in which the Whois class connected to first
        ip_country_set :: a set containing all the countries IPs (under a single domain) are pointing to,
                            excludes first initial connected country

    Return:
        ip_country :: a combined set of both the initial IP country (initial connection in the backend) and
        the country(s) of the other IPs found to point to the domain
        """

    if ip_country_set:
        ip_country = ip_country_set.union(first_connected_country)
    else:
        ip_country = first_connected_country

    return ip_country


def verify_domain_name(assessment_id, domain=None, file=None):
    """ This function takes in a domain name or a file listed with domain names and outputs a file that contains the
            domain name, organisation, registrar, registrant organization, tech organization, name server,
                ip, ip cidr, ip organization, ip city, ip region, ip country, ip custName"

        IF a single domain was entered, then the output will only appear on the terminal

        Output File: recon-output/verify-domain-*-domain-ownership.csv

        Input file: List of domains, where each item is entered line by line with no commas separating them
        Input domain: single domain
    """

    path = create_path("recon-output/verify-domain")

    output_file = f"{path}/{assessment_id}-domain-ownership.csv"

    if file:
        file = file.name

        with open(file, "r") as file_to_read:
            for line in file_to_read:
                if line.strip():  # cleaning file of any empty lines
                    domain = line.strip()
                    whois = who.Whois(whois_query=domain)

                    ips_dict, ip_country, message = verify_domain_helper(whois=whois)

                    # if there are > 1 IP then join countries found to be used for country message
                    country = join_ips_country(ip_country, whois.ip_country)

                    country_message(query=domain, country=country, message=message)

                    if os.path.exists(output_file) is False:  # set headers
                        with open(output_file, "w") as file_to_write:
                            file_to_write.write("domain name; organisation; registrar; registrant organization; "
                                                "tech organization; name server; ip; ip cidr; ip organization; "
                                                "ip city; ip region; ip country; ip custName\n")

                    with open(output_file, "a") as file_to_write:
                        file_to_write.writelines(f'{domain}; {whois.organisation}; {whois.registrar}; '
                                                 f'{whois.registrant_organization}; '
                                                 f'{whois.tech_organization}; {whois.name_server}; {whois.ip}; '
                                                 f'{whois.ip_cidr}; {whois.ip_organization}; '
                                                 f'{whois.ip_city}; {whois.ip_region}; {whois.ip_country}; '
                                                 f'{whois.ip_custname}\n')

                        if ips_dict:
                            for key, ip_whois in ips_dict.items():
                                file_to_write.writelines(f'{domain}; {whois.organisation}; {whois.registrar}; '
                                                         f'{whois.registrant_organization}; '
                                                        f'{whois.tech_organization}; {whois.name_server}; {key}; '
                                                        f'{ip_whois.ip_cidr}; {ip_whois.ip_organization}; '
                                                        f'{ip_whois.ip_city}; {ip_whois.ip_region}; {ip_whois.ip_country}; '
                                                         f'{ip_whois.ip_custname} \n')

        print(f'\n{Bcolors.OKBLUE}More information about each domain can be found in: {output_file}{Bcolors.ENDC}')

    else:  # assume single domain entered
        domain = domain.strip()
        whois = who.Whois(whois_query=domain)
        ips_dict, ip_country, message = verify_domain_helper(whois=whois)
        country = join_ips_country(ip_country, whois.ip_country)

        country_message(query=domain, country=country, message=message)


def enumerate_web_services(assessment_id, file=None):
    """ Web services can take in a file filled with a list of domains, IPs, or mixed (IPs and domains)
        and curl to http and https.

        For every curl response, the status code is extracted and each item in the file is stored with their status code
         in the appropriate outputted file.

         File outputted: *successful.txt, *informational.txt, *redirection.txt, *client_error.txt, *server_error.txt,
                        *reachable.txt (combination of successful, informational, and redirection) , & *unreachable.txt

        Input file: List of domains, IPs, or mixed (IPs and domains) where each item should be
                    entered line by line with no commas separating them
        """
    if file:
        file = file.name  # argparse validates the file exists and is readable, thus can assume we can use it

    path = create_path("recon-output/web-service/")

    # list to test url with both  http and https
    prefix_list = ['http://', 'https://']
    # assigning proper names to status codes
    status_codes_dict = {"informational": [100, 199], "successful": [200, 299],
                         "redirection": [300, 399], "client error": [400, 499],
                         "server error": [500, 599]}
    reachable_code_range = [100, 399]
    specific_codes_dict = {403: "Forbidden", 404: "Not Found", 502: "Bad Gateway", 503: "Service Unavailable",
                           504: "Gateway Timeout"}

    with open(file, "r") as file_to_read:
        for url in file_to_read:
            url = url.strip()
            match = False
            reachable = False
            if url:  # condition to bypass blank lines in file
                for prefix in prefix_list:

                    prefix_url = prefix + url

                    curl_response = subprocess.run(["curl", "-I", prefix_url, "-k", "-s", "--max-time", "4"],
                                                   capture_output=True, text=True).stdout

                    if curl_response:  # making sure you have a response

                        curl_response = curl_response.split(" ")
                        status_code = curl_response[1]

                        if status_code.isdigit():

                            status_code = int(status_code)

                            for general_status, code in status_codes_dict.items():
                                if code[0] <= status_code <= code[1]:
                                    match = True

                                    output_file_name = path + assessment_id + "-web-services-" + general_status + ".txt"
                                    reachable_output_file = path + assessment_id + "-web-services-reachable.txt"

                                    if reachable_code_range[0] <= status_code <= reachable_code_range[1]:
                                        reachable = True

                                    if os.path.exists(output_file_name) is False:  # set headers
                                        with open(output_file_name, "w") as file_to_write:
                                            file_to_write.write("URL, STATUS CODE\n")

                                    if os.path.exists(reachable_output_file) is False:  # set headers
                                        with open(reachable_output_file, "w") as file_to_write:
                                            file_to_write.write("URL, STATUS CODE\n")

                                    with open(output_file_name, "a") as file_to_append, \
                                            open(reachable_output_file, "a") as reachable_file:

                                        if reachable:
                                            reachable_file.write(f"{prefix_url}, {status_code} \n")

                                        file_to_append.write(f"{prefix_url}, {status_code} \n")

                                        if status_code in specific_codes_dict.keys():  # only output specific code mapping to terminal
                                            print(f"{prefix_url} has status code {status_code} "
                                                  f"({specific_codes_dict[status_code]}) - {general_status}")
                                        else:
                                            print(f"{prefix_url} has status code {status_code} - {general_status}")

                    else:  # the connection was timed out and did not get a response
                        status_code = "None"

                    if not match:  # if the status code does not fall in the status_codes_dict then
                        output_file_name = path + assessment_id + "-web-services-unreachable.txt"  # odd cases stored here

                        # Need to change to logger but will keep
                        print(f'{Bcolors.WARNING}{prefix_url} unreachable {Bcolors.ENDC} (maybe timed-out)')

                        if os.path.exists(output_file_name) is False:  # set headers
                            with open(output_file_name, "w") as file_to_write:
                                file_to_write.write("URL, STATUS CODE\n")

                        with open(output_file_name, "a") as file_to_append:
                            file_to_append.write(f"{prefix_url}, {status_code} \n")

            url = ''

    print(f'\n {Bcolors.OKBLUE}Outputted files can be found at: {path}{Bcolors.ENDC}')  # need to change to logger


def enumerate_sub_domains(assessment_id, domain=None):
    """ Takes in a a single domain and uses assetfinder to get a list of subdomains for the domain
    outputs the list of subdomains in recon-output/subdomains/<assessmentid>--subdomains.txt """
    path = create_path("recon-output/subdomains/")
    output_file = f'{path}{assessment_id}-{domain}-subdomains.txt'

    domain = domain.strip()

    subdom_cmd = ["assetfinder", "-subs-only", domain]

    # GNU awk expression: '!x[$0]++'
    # 1. awk syntax has 'pattern {action}' pair expression.
    # 2. '$0' contents of stdin (line)
    # 3. Omitting {...} means awk does default action of '{print $0}'
    # 4. Successful/non-zero pattern match updates values and does action
    # 4. 'x' is an associative array
    # 5. 'x[$0]' will index the 'x' array on line contents
    # 6. Indexing x on unseen $0 adds key-value pair of ($0, 0), return value
    # 7. '!e' will do non-zero check of evaluated expression e
    # 8. 'e++' increment value of expr e after evaluation
    # 9. Upon completion, x will contain number of occurences for each line
    filter_cmd = ["awk", "!x[$0]++"]

    with open(output_file, "wb") as file_to_write:
        subdom_proc = subprocess.Popen(subdom_cmd, stdout=subprocess.PIPE)
        filter_proc = subprocess.Popen(filter_cmd, stdin=subdom_proc.stdout, stdout=subprocess.PIPE)
        for c in iter(lambda: filter_proc.stdout.read(1), b''):
            sys.stdout.buffer.write(c)
            file_to_write.write(c)

    print(f'\n{Bcolors.OKBLUE}Subdomain list stored in: {output_file}{Bcolors.ENDC}')  # need to change to logger


def main():
    parser = argparse.ArgumentParser(description="Scoping Validation Tool",
                                     prog="recon")
    parser.add_argument('assessment_id', type=str,
                        help='The Assessement ID - this is required')  # pre-appended to output files

    # creating sub parsers
    subparser = parser.add_subparsers(dest='cmd')
    verify_ip = subparser.add_parser('verify_ip', help="-i, --ip  (A single IP to be verified) "
                                                       "OR -f, --file (A File that contains a "
                                                       "list of ips to be verified)")
    verify_domain = subparser.add_parser('verify_domain', help="-d, --domain (A single domain to be verified) "
                                                               "OR -f, --file (A File that contains a list of "
                                                               "domains to be verified)")
    web_services = subparser.add_parser('web_services', help="-f, --file (A File that contains a list of domains, ips, "
                                                             "or a mixed list, containing both ips and domains, "
                                                             "to enumerate web services)")
    subdomains = subparser.add_parser('subdomains', help="-d, --domain (A single domain to enumerate sub domains)")

    # Options that need to be mutually exclusive
    verify_ip.add_mutually_exclusive_group()
    verify_domain = verify_domain.add_mutually_exclusive_group()
    subdomains = subdomains.add_mutually_exclusive_group()

    # arguments for every subparser
    verify_ip.add_argument('-i', '--ip', type=str,
                           help='A single IP to be verified')
    verify_ip.add_argument('-f', '--file', type=argparse.FileType('r'),
                           help='A File that contains a list of ips to be verified')

    verify_domain.add_argument('-d', '--domain', type=str,
                               help='A single domain to be verified')
    verify_domain.add_argument('-f', '--file', type=argparse.FileType('r'),
                               help='A File that contains a list of domains to be verified')

    web_services.add_argument('-f', '--file', type=argparse.FileType('r'),
                              help='A File that contains a list of domains, ips, '
                                   'or a mixed list (containing both ips and domains) to enumerate web services',
                              required=True)

    subdomains.add_argument('-d', '--domain', type=str,
                            help='A single domain to enumerate sub domains')

    args = parser.parse_args()

    if args.cmd == 'verify_ip':
        verify_ip_address(args.assessment_id, args.ip, args.file)

    if args.cmd == 'verify_domain':
        verify_domain_name(args.assessment_id, args.domain, args.file)

    if args.cmd == 'web_services':
        enumerate_web_services(args.assessment_id, args.file)  # accepts file only

    if args.cmd == 'subdomains':
        enumerate_sub_domains(args.assessment_id, args.domain)

    # TODO: We need a new option to install dependencies


if __name__ == '__main__':
    exit(main())




