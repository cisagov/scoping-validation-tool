"""
Scope Validation Tool v1.2.0

Copyright 2022 Scope Validation Tool Contributors, All Rights Reserved

License-Identifier: MIT (SEI)-style

Please see additional acknowledgments (including references to third party source code, object code, documentation and other files) in the license.txt file or contact permission@sei.cmu.edu for full terms.

Created, in part, with funding and support from the United States Government. (see Acknowledgments file).

DM22-0416
"""
# some regex patterns were copied from joepie91

# Whois info for domains
domain_regex_dict = {"registrar": ['registrar:\s*(?P<val>.+)',
                                   'Sponsoring Registrar Organization:\s*(?P<val>.+)',
                                   'Registered through:\s?(?P<val>.+)',
                                   'Registrar Name[.]*:\s?(?P<val>.+)', 'Record maintained by:\s?(?P<val>.+)',
                                   'Registration Service Provided By:\s?(?P<val>.+)',
                                   'Registrar of Record:\s?(?P<val>.+)',
                                   'Domain Registrar :\s?(?P<val>.+)', 'Registration Service Provider: (?P<val>.+)',
                                   '\tName:\t\s(?P<val>.+)'],
                     "registrant": ["(?:Registrant Organization:[ ]*(?P<organization>.*)\n)",
                                    # WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
                                    "Registrant\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n",
                                    # internet.bs
                                    " Registrant Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)",
                                    # Whois.com
                                    "owner-id:[ ]*(?P<handle>.*)\n(?:owner-organization:[ ]*(?P<organization>.*)\n)?owner-name:[ ]*(?P<name>.*)\nowner-street:[ ]*(?P<street>.*)\nowner-city:[ ]*(?P<city>.*)\nowner-zip:[ ]*(?P<postalcode>.*)\nowner-country:[ ]*(?P<country>.*)\n(?:owner-phone:[ ]*(?P<phone>.*)\n)?(?:owner-fax:[ ]*(?P<fax>.*)\n)?owner-email:[ ]*(?P<email>.*)",
                                    # InterNetworX
                                    "Registrant:\n registrant_org: (?P<organization>.*)\n registrant_name: (?P<name>.*)\n registrant_email: (?P<email>.*)\n registrant_address: (?P<address>.*)\n registrant_city: (?P<city>.*)\n registrant_state: (?P<state>.*)\n registrant_zip: (?P<postalcode>.*)\n registrant_country: (?P<country>.*)\n registrant_phone: (?P<phone>.*)",
                                    # Bellnames
                                    "Holder of domain name:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\nContractual Language",
                                    # nic.ch
                                    "\n\n(?:Owner)?\s+: (?P<name>.*)\n(?:\s+: (?P<organization>.*)\n)?\s+: (?P<street>.*)\n\s+: (?P<city>.*)\n\s+: (?P<state>.*)\n\s+: (?P<country>.*)\n",
                                    # nic.io
                                    "Contact Information:\n\[Name\]\s*(?P<name>.*)\n\[Email\]\s*(?P<email>.*)\n\[Web Page\]\s*(?P<url>.*)\n\[Postal code\]\s*(?P<postalcode>.*)\n\[Postal Address\]\s*(?P<street1>.*)\n(?:\s+(?P<street2>.*)\n)?(?:\s+(?P<street3>.*)\n)?\[Phone\]\s*(?P<phone>.*)\n\[Fax\]\s*(?P<fax>.*)\n",
                                    # jprs.jp
                                    "g\. \[Organization\]               (?P<organization>.+)\n",
                                    # .co.jp registrations at jprs.jp
                                    "Registrant ID:(?P<handle>.*)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Address1:(?P<street1>.*)\n(?:Registrant Address2:(?P<street2>.*)\n)?(?:Registrant Address3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\n(?:Registrant State/Province:(?P<state>.*)\n)?(?:Registrant Postal Code:(?P<postalcode>.*)\n)?Registrant Country:(?P<country>.*)\nRegistrant Country Code:.*\nRegistrant Phone Number:(?P<phone>.*)\n(?:Registrant Facsimile Number:(?P<facsimile>.*)\n)?Registrant Email:(?P<email>.*)",
                                    # .US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
                                    "Registrant\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?",
                                    # nic.it
                                    "  Organisation Name[.]* (?P<name>.*)\n  Organisation Address[.]* (?P<street1>.*)\n  Organisation Address[.]* (?P<street2>.*)\n(?:  Organisation Address[.]* (?P<street3>.*)\n)?  Organisation Address[.]* (?P<city>.*)\n  Organisation Address[.]* (?P<postalcode>.*)\n  Organisation Address[.]* (?P<state>.*)\n  Organisation Address[.]* (?P<country>.*)",
                                    # Melbourne IT (what a horrid format...)
                                    "Registrant:[ ]*(?P<name>.+)\n[\s\S]*Eligibility Name:[ ]*(?P<organization>.+)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n",
                                    # .au business
                                    "Eligibility Type:[ ]*Citizen\/Resident\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n",
                                    # .au individual
                                    "Registrant:[ ]*(?P<organization>.+)\n[\s\S]*Eligibility Type:[ ]*(Higher Education Institution|Company|Incorporated Association|Other)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n",
                                    # .au educational, company, 'incorporated association' (non-profit?), other (spotted for linux.conf.au, unsure if also for others)
                                    "    Registrant:\n        (?P<name>.+)\n\n    Registrant type:\n        .*\n\n    Registrant's address:\n        The registrant .* opted to have",
                                    # Nominet (.uk) with hidden address
                                    "    Registrant:\n        (?P<name>.+)\n\n[\s\S]*    Registrant type:\n        .*\n\n    Registrant's address:\n        (?P<street1>.+)\n(?:        (?P<street2>.+)\n(?:        (?P<street3>.+)\n)??)??        (?P<city>[^0-9\n]+)\n(?:        (?P<state>.+)\n)?        (?P<postalcode>.+)\n        (?P<country>.+)\n\n",
                                    # Nominet (.uk) with visible address
                                    "Domain Owner:\n\t(?P<organization>.+)\n\n[\s\S]*?(?:Registrant Contact:\n\t(?P<name>.+))?\n\nRegistrant(?:'s)? (?:a|A)ddress:(?:\n\t(?P<street1>.+)\n(?:\t(?P<street2>.+)\n)?(?:\t(?P<street3>.+)\n)?\t(?P<city>.+)\n\t(?P<postalcode>.+))?\n\t(?P<country>.+)(?:\n\t(?P<phone>.+) \(Phone\)\n\t(?P<fax>.+) \(FAX\)\n\t(?P<email>.+))?\n\n",
                                    # .ac.uk - what a mess...
                                    "Registrant ID: (?P<handle>.+)\nRegistrant: (?P<name>.+)\nRegistrant Contact Email: (?P<email>.+)",
                                    # .cn (CNNIC)
                                    "Registrant contact:\n  (?P<name>.+)\n  (?P<street>.*)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n\n",
                                    # Fabulous.com
                                    "registrant-name:\s*(?P<name>.+)\nregistrant-type:\s*(?P<type>.+)\nregistrant-address:\s*(?P<street>.+)\nregistrant-postcode:\s*(?P<postalcode>.+)\nregistrant-city:\s*(?P<city>.+)\nregistrant-country:\s*(?P<country>.+)\n(?:registrant-phone:\s*(?P<phone>.+)\n)?(?:registrant-email:\s*(?P<email>.+)\n)?",
                                    # Hetzner
                                    "Registrant Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
                                    # GAL Communication
                                    "Contact Information : For Customer # [0-9]+[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n",
                                    # GAL Communication alternative (private WHOIS) format?
                                    "Registrant:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n",
                                    # Akky (.com.mx)
                                    "   Registrant:\n      (?P<name>.+)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)",
                                    # .am
                                    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>[^.,]+), (?P<district>.+), (?P<state>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
                                    # .co.th, format 1
                                    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
                                    # .co.th, format 2
                                    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+)\n(?:(?P<street2>.+)\n)?(?:(?P<street3>.+)\n)?.+?, (?P<district>.+)\n(?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
                                    # .co.th, format 3
                                    "Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+),? (?P<state>[A-Z]{2,3})(?: [A-Z0-9]+)?\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n",
                                    # .co.th, format 4
                                    "   Registrant:\n      (?P<organization>.+)\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n      (?P<street>.*)\n      (?P<city>.+), (?P<state>[^,\n]*)\n      (?P<country>.+)\n",
                                    # .com.tw (Western registrars)
                                    "Registrant:\n(?P<organization1>.+)\n(?P<organization2>.+)\n(?P<street1>.+?)(?:,+(?P<street2>.+?)(?:,+(?P<street3>.+?)(?:,+(?P<street4>.+?)(?:,+(?P<street5>.+?)(?:,+(?P<street6>.+?)(?:,+(?P<street7>.+?))?)?)?)?)?)?,(?P<city>.+),(?P<country>.+)\n\n   Contact:\n      (?P<name>.+)   (?P<email>.+)\n      TEL:  (?P<phone>.+?)(?:(?:#|ext.?)(?P<phone_ext>.+))?\n      FAX:  (?P<fax>.+)(?:(?:#|ext.?)(?P<fax_ext>.+))?\n",
                                    # .com.tw (TWNIC/SEEDNET, Taiwanese companies only?)
                                    "Registrant Contact Information:\n\nCompany English Name \(It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents\):(?P<organization1>.+)\nCompany Chinese name:(?P<organization2>.+)\nAddress: (?P<street>.+)\nCountry: (?P<country>.+)\nEmail: (?P<email>.+)\n",
                                    # HKDNR (.hk)
                                    "Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Street1:(?P<street1>.+?)\n(?:Registrant Street2:(?P<street2>.+?)\n(?:Registrant Street3:(?P<street3>.+?)\n)?)?Registrant City:(?P<city>.+)\nRegistrant State:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.+)\nRegistrant Country:(?P<country>[A-Z]+)\nRegistrant Phone:(?P<phone>.*?)\nRegistrant Fax:(?P<fax>.*)\nRegistrant Email:(?P<email>.+)\n",
                                    # Realtime Register
                                    "owner:\s+(?P<name>.+)",  # .br
                                    "person:\s+(?P<name>.+)",  # nic.ru (person)
                                    "org:\s+(?P<organization>.+)",  # nic.ru (organization)
                                    ],

                     "tech_org": ['tech organization:\s*(?P<val>.+)', 'tech org:\s*(?P<val>.+)'],

                     "name_server": ['Name Server:\s*(?P<val>.+)',
                                     'Nameservers:[ ]*(?P<val>[^ ]+)',
                                     '(?<=[ .]{2})(?P<val>([a-z0-9-]+\.)+[a-z0-9]+)(\s+([0-9]{1,3}\.){3}[0-9]{1,3})',
                                     'nameserver:\s*(?P<val>.+)',
                                     #'nserver:\s*(?P<val>[^[\s]+)',
                                     'Name Server[.]+ (?P<val>[^[\s]+)'
                                     #  'Hostname:\s*(?P<val>[^\s]+)',
                                     #  'DNS[0-9]+:\s*(?P<val>.+)',
                                     # '   DNS:\s*(?P<val>.+)',
                                     #'Nserver:\s*(?P<val>.+)'
                                     ],

                     "organisation": ['organisation:\s*(?P<val>.+)']  # for gov domains
                     }

# whois info for IPs
ip_regex_dict = {"ip_cidr": ['CIDR:\s*(?P<val>.+)'],
                 "ip_organization": ['Organization:\s*(?P<val>.+)'],
                 "ip_region": ['StateProv:\s*(?P<val>.+)'],  # this is the state
                 "ip_city": ['City:\s*(?P<val>.+)'],
                 "ip_country": ['country:\s*(?P<val>.+)'],
                 "ip_custname": ['CustName:\s*(?P<val>.+)']}  # only appears if running whois on Kali not MacOS
