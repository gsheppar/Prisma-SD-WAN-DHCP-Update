#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import os
import datetime
from datetime import datetime, timedelta
import sys
import csv
from csv import DictReader
import json


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: DHCP Update'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

    
def dhcp(cgx, list_of_csv):
    
    for site in cgx.get.sites().cgx_content['items']:
        site_dhcp_update = False
        site_dhcp_list = []
        for dhcp in list_of_csv:
            if site["name"] == dhcp["site_name"]:
                site_dhcp_list.append(dhcp)
        print("Checking site " + site["name"])
        for dhcp in cgx.get.dhcpservers(site_id=site["id"]).cgx_content['items']:
            for dhcp_check in site_dhcp_list:
                if dhcp["subnet"] == dhcp_check["subnet"]:
                    #print("--Checking DHCP subnet " + dhcp["subnet"])
                    update_dhcp = False
                    ### DHCP Description Check ###
                    if dhcp_check["description"] == "":
                        final = None
                    else:
                        final = dhcp_check["description"]
                    if dhcp["description"] != final:
                        dhcp["description"] = final
                        update_dhcp = True
                    ### DHCP Domain Check ###
                    if dhcp_check["domain_name"] == "":
                        final = None
                    else:
                        final = dhcp_check["domain_name"]
                    if dhcp["domain_name"] != final:
                        dhcp["domain_name"] = final
                        update_dhcp = True
                    ### DHCP Lease Time Check ###
                    final = int(dhcp_check["default_lease_time"])
                    if dhcp["default_lease_time"] != final:
                        dhcp["default_lease_time"] = final
                        update_dhcp = True
                    ### DHCP Max Lease Time Check ###
                    final = int(dhcp_check["max_lease_time"])
                    if dhcp["max_lease_time"] != final:
                        dhcp["max_lease_time"] = final
                        update_dhcp = True
                    ### DHCP Range Check ###
                    final = dhcp_check["ip_ranges"].replace("'", '"')
                    final = json.loads(final)
                    if len(dhcp["ip_ranges"]) == len(final) and all(x in final for x in dhcp["ip_ranges"]):
                        pass    
                    else:
                        dhcp["ip_ranges"] = final
                        update_dhcp = True
                    ### DHCP DNS Check ###
                    final = dhcp_check["dns_servers"].replace("'", '"')
                    final = json.loads(final)
                    if len(dhcp["dns_servers"]) == len(final) and all(x in final for x in dhcp["dns_servers"]):
                        pass    
                    else:
                        dhcp["dns_servers"] = final
                        update_dhcp = True
                    ### DHCP Update Check ###
                    if update_dhcp:
                        resp = cgx.put.dhcpservers(site_id=site["id"], dhcpserver_id=dhcp["id"], data = dhcp)
                        if not resp:
                            print("--ERROR updating DHCP on " + site["name"] + " subnet " + dhcp["subnet"])
                            print(str(jdout(resp)))
                        else:
                            print("--UPDATING DHCP on " + site["name"] + " subnet " + dhcp["subnet"])
                            site_dhcp_update = True       
    
    return

                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    
    list_of_csv = []
    with open('dhcp_list.csv', 'r') as data:
      for line in csv.DictReader(data):
          list_of_csv.append(line)
    
    dhcp(cgx, list_of_csv) 
    # end of script, run logout to clear session.
    print("End of script. Logout!")
    #cgx_session.get.logout()

if __name__ == "__main__":
    go()