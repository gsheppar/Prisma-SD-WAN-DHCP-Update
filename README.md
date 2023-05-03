# Prisma SD-WAN DHCP Update (Preview)
The purpose of this script is to be able to export all site DHCP servers, make updates and then push the configuration changes back in.

- DHCP Description
- DNS domain_name
- DHCP default_lease_time
- DNS max_lease_time
- DHCP ip_ranges
- DNS dns_servers

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 Update line 192/193
    syslog_profile = "Demo-Syslog"
    domain = "US-East"
 
 1. ./dhcp_get_.py
      - Will get a list of all dhcp servers per site
	  - exported as dhcp_list.csv
 2. ./dhcp_update.py
      - Based on dhcp_list.csv if will update any changed values for the DHCP server
 
 

### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
