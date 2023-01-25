"""
Scope Validation Tool v1.2.0

Copyright 2022 Scope Validation Tool Contributors, All Rights Reserved

License-Identifier: MIT (SEI)-style

Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

DM22-0416
"""

import re
import subprocess
import sys

import dns.resolver
import dns.reversename

from recon.whois_parser import domain_regex_dict, ip_regex_dict


class Whois:
    # helper class Set to override set.__str__(self) method
    class Set(set):
        def __str__(self):
            return ", ".join(map(repr,self))

    def __init__(self, whois_query="google.com"):
        """
        Initial instance vars:
        - Mark as None to initialize
        - If info is "REDACTED FOR PRIVACY" assign var lowercase str "private"
        """

        # query attributes (see RI below)
        self.whois_query = whois_query
        self.ip = None
        self.domain = None

        # values assigned for querying domain
        self.registrar = None
        self.registrant_organization = None
        self.tech_organization = None
        self.name_server = None
        self.organisation = None  # Mainly needed for .gov tlds

        # values assigned for querying ip addr
        self.ip_country = None
        self.ip_city = None
        self.ip_region = None  # the state
        self.ip_cidr = None
        self.ip_organization = None
        self.ip_custname = None
        self.ips_set = None  # If a given domain points to more than one IP then IPs are stored here

        # values assigned using dns module (nslookup)
        self.fqdn = None

        # whois output attributes
        self.whois_dict = {}  # dictionary whois output
        self.raw_domain_whois = ""
        self.raw_ip_whois = ""

        # whois_query regex matching
        pat = '([0-9]{1,3}\.){3}[0-9]{1,3}'
        re_obj = re.compile(pat)
        mat_obj = re_obj.match(whois_query)

        # REPRESENTATION INVARIANT (RI):
        # whois_query input is exclusively an ip addr or a domain (xor)
        # bool(self.ip) != bool(self.domain) ==> true
        if mat_obj:
            self.ip = whois_query
        else:
            self.domain = whois_query

        # TODO: Check what env/OS is running the script and act accordingly
        #       (ex. is whois installed?)

        self.query()

    def check_whois_install(self):
        """ Does whois exist on local machine?"""

        # TODO: implement
        pass

    @staticmethod
    def whois_regex_process(patterns, data):
        """ Iterate through patterns, match against data """

        result_list = []
        for pattern in patterns:
            try:
                my_match = re.findall(pattern, data, re.IGNORECASE)
                my_match = [x.lower() for x in my_match]
                # print(f'my match: {my_match}')
                if my_match:
                    result_list += my_match
            except AttributeError:
                continue  # print(None)
        if not result_list:
            return None
        else:
            return Whois.Set(result_list)

    def filter_domain_whois(self):
        """ Filters raw data for domain queries"""

        self.whois_dict['domain'] = self.domain
        self.registrar = self.whois_regex_process(
            domain_regex_dict["registrar"], self.raw_domain_whois)
        self.whois_dict['registrar'] = self.registrar
        self.registrant_organization = self.whois_regex_process(
            domain_regex_dict["registrant"], self.raw_domain_whois)
        self.whois_dict['registrant_organization'] = (
            self.registrant_organization)
        self.tech_organization = self.whois_regex_process(
            domain_regex_dict["tech_org"], self.raw_domain_whois)
        self.whois_dict['tech_organization'] = self.tech_organization
        self.name_server = self.whois_regex_process(
            domain_regex_dict["name_server"], self.raw_domain_whois)
        self.whois_dict['name_server'] = self.name_server
        self.organisation = self.whois_regex_process(
            domain_regex_dict["organisation"], self.raw_domain_whois)
        self.whois_dict['organisation'] = self.organisation

    def filter_ip_whois(self):
        """ Filters raw data for ip queries"""

        self.whois_dict['ip'] = self.ip
        self.ip_cidr = self.whois_regex_process(
            ip_regex_dict["ip_cidr"], self.raw_ip_whois)
        self.whois_dict['ip_cidr'] = self.ip_cidr
        self.ip_organization = self.whois_regex_process(
            ip_regex_dict["ip_organization"], self.raw_ip_whois)
        self.whois_dict['ip_organization'] = self.ip_organization
        self.ip_city = self.whois_regex_process(
            ip_regex_dict["ip_city"], self.raw_ip_whois)
        self.whois_dict['ip_city'] = self.ip_city
        self.ip_country = self.whois_regex_process(
            ip_regex_dict["ip_country"], self.raw_ip_whois)
        self.whois_dict['ip_country'] = self.ip_country
        self.ip_region = self.whois_regex_process(
            ip_regex_dict["ip_region"], self.raw_ip_whois)
        self.whois_dict['ip_region'] = self.ip_region
        self.ip_custname = self.whois_regex_process(
            ip_regex_dict["ip_custname"], self.raw_ip_whois)
        self.whois_dict['ip_custname'] = self.ip_custname

        self.whois_dict['fqdn'] = self.fqdn

    def lookup(self):
        """ 1. Use dns.reversename to lookup FQDN for self.ip, or
            2. Use dns.resolver to lookup ip addr for self.domain
        """
        try:
            if self.ip:
                # only return fqdn if resolver is able to find domain
                # ans = dns.resolver.resolve(self.ip)
                name = dns.reversename.from_address(self.ip).to_text()
                return name
            else:
                ans = dns.resolver.resolve(self.domain).rrset
                # rrset elts have type dns.rdtypes.IN.A.A
                # rr.to_text() returns 'address' slot
                first_ip = ans[0].to_text()  # hitting first IP

                if len(ans) > 1:  # if there is more than on IP then store in set
                    self.ips_set = Whois.Set([rr.to_text() for rr in ans])

                return first_ip  # default to return the first instance for now
        # except dns.resolver.NXDOMAIN as e:  #  commenting out until fqdn resolves
            # print("Whois.lookup() NXDOMAIN:", e, file=sys.stderr)
        except dns.resolver.NoNameservers as e:
            print("Whois.lookup() Warning:", e, file=sys.stderr)
        except dns.exception.DNSException as e:
            print("Whois.lookup() Error - DNS Exception:", e, file=sys.stderr)
        except dns.exception.SyntaxError as e:
            print("Whois.lookup() Error - SyntaxError:", e, file=sys.stderr)

    def query(self):
        """ Takes in domain or IP to query """

        if self.ip:
            self.raw_ip_whois = subprocess.run(['whois', self.ip],
                capture_output=True, text=True).stdout
            self.filter_ip_whois()
            # self.whois_dict['fqdn'] = self.lookup() TODO: resolve fqdn issue
        else:
            self.raw_domain_whois = subprocess.run( ['whois', self.domain],
                capture_output=True, text=True).stdout
            self.filter_domain_whois()
            assoc_ip_addr = self.lookup()

            if assoc_ip_addr:
                self.ip = assoc_ip_addr
                self.raw_ip_whois = subprocess.run(['whois', self.ip],
                    capture_output=True, text=True).stdout
                self.filter_ip_whois()

    def query_file(self, file):
        "Determine what files we can handle and in what format"

        # TODO: for ea domain/ip listed, call self.query(), filter accordingly
        # Q1: Might want to do this recursively?
        # A1: Probably. As architected, each instance of Whois class will have
        #     its own query (string) and results (dictionaries)
        pass


if __name__ == '__main__':
    query = 'amazon.com'  # '129.6.13.49'

    whois = Whois(whois_query=query)
    print(f'My output from custom whois class: \n\t{whois.whois_dict}')
