# Scoping Validation Tool
## About
The Scoping Validation Tool leverages Whois and a handful of manual techniques 
to obtain useful information during an assessment.

This script assumes you have access to the internet and the following installed:
* Python3
* pip3
* assetfinder 
* curl
* whois

Find below a quick-rundown on the script options, information produced, and where it's stored during each step.


## Setup
```bash
# Install recon executable
pip3 install .

# If pip warns of missing PATH entry '$HOME/.local/bin', then append it to PATH
echo $PATH
cp -vf $HOME/.zshrc $HOME/.zshrc.orig
echo "export PATH=\$PATH:\$HOME/.local/bin" >> $HOME/.zshrc
source ~/.zshrc
echo $PATH
```



## Help Menu
The executable file for SVT is ```$HOME/.local/bin/recon```. Using the ```recon -h``` command will display the help menu

```commandline
$ recon -h
usage: recon [-h] assessment_id {verify_ip,verify_domain,web_services,subdomains} ...

Scoping Validation Tool

positional arguments:
  assessment_id         The Assessement ID - this is required
  {verify_ip,verify_domain,web_services,subdomains}
    verify_ip           -i, --ip (A single IP to be verified) OR -f, --file (A File that
                        contains a list of ips to be verified)
    verify_domain       -d, --domain (A single domain to be verified) OR -f, --file (A File that
                        contains a list of domains to be verified)
    web_services        -f, --file (A File that contains a list of domains, ips, or a mixed
                        list, containing both ips and domains, to enumerate web services)
    subdomains          -d, --domain (A single domain to enumerate sub domains)

optional arguments:
  -h, --help            show this help message and exit
```

## Menu Option: verify_ip 
**Objective:** The purpose of this option is to validate the scope of an IP or IPs entered by extracting information from *Whois* 
to determine what country an IP is from.


```verify_ip``` takes in an IP or a file listed with IPs and outputs a file that contains the IP, 
organization, CIDR, city region, country, and custName. Additionally it outputs to the terminal what country an IP is from, if it was able to extract it.

If a single IP was entered, then the output will **only** appear on the terminal and will **not** be stored in a file

Output File: *recon-output/verify-address/<assessmentID>-Location-Lookups.csv*

Input File: List of ips, where each item is entered line by line with no commas separating them

Input IP: Single ip

##### Example On How to Run With a File That Contains IPs:

You can pass a file in the ```verify_ip``` option using the ```-f``` or the ```--file``` flag

```commandline
$ recon RVA-123 verify_ip -f test-data/10-ips.txt
 23.53.112.15 location resides in the United States. Country = 'us'
	IP Organization: 'akamai technologies, inc. (akamai)'

 76.209.191.5 location resides in the United States. Country = 'us'
	IP Organization: 'at&t corp. (ac-3280)'
	CustName: 'irvine ranch water district'

 123.151.137.18 location resides outside the United States. Country = 'zz', 'cn'
	IP Organization: None

 205.251.242.103 location resides in the United States. Country = 'us'
	IP Organization: 'amazon.com, inc. (amazon-4)'
...

More information about each IP can be found in: recon-output/verify-address/RVA-123-Location-Lookups.csv
```

##### Example On How to Run With a Single IP:

You can pass an IP in the ```verify_ip``` option using the ```-i``` or the ```--ip``` flag

```commandline
$ recon RVA-123 verify_ip -i 166.94.11.36
 166.94.11.36 location resides in the United States. Country = 'us'
	IP Organization: 'fairfax county government (fcgccc)'
```


## Menu Option: verify_domain
**Objective:** The purpose of this option is to validate the scope of a domain or domains entered by extracting information from *Whois* 
to determine what country a domain's IP is from. Note that not all domains support reverse lookups - if this is the 
case, then the tool will output that it could not determine the domain's location.


```verify_domain``` takes in a domain name or a file listed with domain names and outputs a file that contains the
domain name, organisation, registrar, registrant organization, tech organization, name server,
ip, ip cidr, ip organization, ip city, ip region, ip country, ip custname"

If a single domain was entered, then the output will **ONLY** appear on the terminal and **not** store in a file

Output File: *recon-output/verify-domain/<assessmentID>-domain-ownership.csv*

Input File: List of domains, where each item is entered line by line with no commas separating them

Input Domain: Single domain

##### Example On How to Run With a File That Contains domains:

You can pass a file in the ```verify_domain``` option using the ```-f``` or the ```--file``` flag

```commandline
$ recon RVA-123 verify_domain -f test-data/10-domains.txt
 yahoo.com location resides in the United States. Country = 'us'
	Domain Organisation: 'verisign global registry services'
	IP: 74.6.143.26
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 74.6.143.25
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 98.137.11.163
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 98.137.11.164
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 74.6.231.21
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 74.6.231.20
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'

Whois.lookup() Error - DNS Exception: The DNS query name does not exist: 88888-NOT-a-domain.
 88888-NOT-a-domain could not determine location. Country extracted is None.

 mural.co location resides outside the United States. Country = 'us', 'nl', 'se'
	Domain Organisation: None
	IP: 146.75.30.132
		IP Organization: 'ripe network coordination centre (ripe)'
		IP Country: 'us', 'nl', 'se'
...

More information about each domain can be found in: recon-output/verify-domain/RVA-123-domain-ownership.csv
```

##### Example On How to Run With a Single Domain:

You can pass a single domain in the ```verify_domain``` option using the ```-d``` or the ```--domain``` flag

```commandline
$ recon RVA-123 verify_domain -d yahoo.com
 yahoo.com location resides in the United States. Country = 'us'
	Domain Organisation: 'verisign global registry services'
	IP: 74.6.231.20
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 98.137.11.164
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 74.6.231.21
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 98.137.11.163
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 74.6.143.26
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'
	IP: 74.6.143.25
		IP Organization: 'oath holdings inc. (oh-207)'
		IP Country: 'us'

```


## Menu Option: web_services
**Objective:** The purpose of this option is to enumerate web services IPs or domains and curl to http and https. 
Note that some curl responses will be timed out so this tool will deem them as unreachable. 


```web_services``` takes in a file filled with a list of domains, IPs, or mixed (IPs and domains) 
and curl to http and https.

For every curl response, the status code is extracted and each item in the file is stored with their status code
in the appropriate outputted file.

File Outputted: *successful.txt, *informational.txt, *redirection.txt, *client_error.txt, *server_error.txt,
*reachable.txt (combination of successful, informational, and redirection) , & *unreachable.txt

Input File: List of domains, IPs, or mixed (IPs and domains) where each item should be entered line by line with 
no commas separating them

##### Example On How to Run With a File:

You can pass a file in the ```web_services``` option using the ```-f``` or the ```--file``` flag

```commandline
$ recon RVA-123 web_services -f test-data/10-ips.txt
    http://23.53.112.15 has status code 400
    https://23.53.112.15 has status code 200
    http://50.87.150.46 has status code 302
    https://50.87.150.46 has status code 200
    http://170.164.46.152 unreachable  (maybe timed-out)
    https://170.164.46.152 has status code 200
    http://170.164.46.153 has status code 503
    https://170.164.46.153 has status code 200
    http://170.164.46.154 unreachable  (maybe timed-out)
    https://170.164.46.154 has status code 200
    http://104.16.16.221 has status code 403
    https://104.16.16.221 has status code 200
    http://34.73.153.179 has status code 404
    https://34.73.153.179 has status code 200
    http://166.94.11.36 has status code 302
    https://166.94.11.36 has status code 200
    http://123.151.137.18 has status code 503
    https://123.151.137.18 has status code 200
    http://205.251.242.103 has status code 301
    https://205.251.242.103 has status code 200

 Outputted files can be found at: recon-output/web-service/
```


## Menu Option: subdomains
**Objective:** Takes in a a single domain and uses *assetfinder* to get a list of subdomains for the domain
    outputs the list of subdomains in recon-output/subdomains/<assessmentid>--subdomains.txt

##### Example On How to Run:

You can pass a domain in the ```subdomains``` option using the ```-d``` or the ```--domain``` flag

```commandline
$ python recon.py RVA-123 subdomains -d aldi.us
aldi.us
mobile.wfm.aldi.us
gateway.aldi.us
atcloud.prod.aldi.us
ame.aldi.us
astute-srm-test.aldi.us
survey.aldi.us
astute-srm-live.aldi.us
flipp.aldi.us
...
Subdomain list stored in: recon-output/subdomains/RVA-123-aldi.us-subdomains.txt
```


## License
Scope Validation Tool v1.2.0

Copyright 2022 Scope Validation Tool Contributors, All Rights Reserved

License-Identifier: MIT (SEI)-style

Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

DM22-0416
