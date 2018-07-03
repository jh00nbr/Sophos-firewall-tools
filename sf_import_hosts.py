#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Tool to import objects of hosts in the Firewall XG Sophos

# -------------------------------------------------
# Author: Jhonathan Davi A.K.A jh00nbr
# Insightl4b: lab.insightsecurity.com.br
# jh00nbr: http://jhonathandavi.com.br
# Github: github.com/jh00nbr
# Twitter @jh00nbr
# -------------------------------------------------

import requests
import urllib3
import argparse
import re
import sys

__author__ = "Jhonathan Davi A.K.A jh00nbr"
__email__ = "jdavi@insightsecurity.com.br"

urllib3.disable_warnings() # Disable warning alerts requests SSL 

parser = argparse.ArgumentParser(prog='SFimport objects')

parser.add_argument("-l", "--listobjects", help="List with objects to be imported.", default="objects.list", required=True)
parser.add_argument("-gw", "--hostgw", help="Host firewall Sophos.", required=True)
parser.add_argument("-host", "--importhost", help="Import option", default=1,action="store_true",required=False)
parser.add_argument("-u", "--user", help="User firewall Sophos.", default="admin", required=True)
parser.add_argument("-p", "--passwd", help="Password firewall Sophos.", required=True)
parser.add_argument("-P", "--port", help="Web port Sophos", required=True)

args = parser.parse_args()

list_object = args.listobjects
import_host = args.importhost
host_fw = args.hostgw
user_fw = args.user
passwd_fw = args.passwd
default_port = args.port

_CONFIGS = {'username_fw': user_fw, 'passwd_fw': passwd_fw, 'host_fw': host_fw, 'default_port': default_port}
_COLORS = {'MAGENTA':'\033[35mMagenta','BLUE': '\033[34m', 'OK' : '\033[92m', 'ERRO' : '\033[91m', 'WARNING' : '\033[93m', 'UNDERLINE':'\033[4m','ENDC' : '\033[0m'}


def import_objects(file):
	read_file = [re.split(r' \s+', x.strip()) for x in open(file, "r").readlines()]
	OBJECT_EXCEPTION = []
	OBJECTS = []

	for x in read_file:
	    REGEX_IP = re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',x[0]) # Regex to Verify if exist ip address in object name
	    if REGEX_IP:
	            OBJECT_EXCEPTION.append(x)               
	    try:
	            OBJECT_NAME = x[0]
	            OBJECT_VALUE = x[1]                
	            OBJECTS.append({ OBJECT_NAME : OBJECT_VALUE })
	    except:
	            pass
	return OBJECTS


def create_iphost(nameObj, ipAddr, type_obj='IP_HOST'): # Create a object type Ip host
	NAME_OBJECT = nameObj
	IP_ADDRESS = ipAddr

	try:
		r_api = requests.get("https://{host_fw}:{defaultport}/webconsole/APIController?reqxml=<Request><Login><Username>{username}</Username><Password>{password}</Password></Login><Set operation='add'><IPHost><Name>{name}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{ipaddress}</IPAddress></IPHost></Set></Request>".format(host_fw=_CONFIGS['host_fw'],defaultport=_CONFIGS['default_port'],username=_CONFIGS['username_fw'], password=_CONFIGS['passwd_fw'], name=NAME_OBJECT, ipaddress=IP_ADDRESS),verify=False)
		if 'API operations are not allowed from the requester IP address' in r_api.content:
			print('{0}[+]{1} API operations are not allowed from the requester IP address'.format(_COLORS['OK'],_COLORS['ENDC'],NAME_OBJECT))
			sys.exit(0)
		if 'Configuration applied successfully' in r_api.content:
			print('{0}[+]{1} [{2}] [{3}] [{4}] Object added successfully'.format(_COLORS['OK'],_COLORS['ENDC'],NAME_OBJECT, IP_ADDRESS, type_obj))
		elif 'Operation failed. Entity having same name already exists':
			print('{0}[-]{1} [{2}] [{3}] [{4}] An object with this name already exists'.format(_COLORS['ERRO'],_COLORS['ENDC'],NAME_OBJECT, IP_ADDRESS, type_obj))
		else:
			print('{0}[-]{1} unknown erro {2}]'.format(_COLORS['ERRO'] ,_COLORS['ENDC'], NAME_OBJECT))
	except Exception as e:
		print(NAME_OBJECT, e)


if __name__ == '__main__':

	if import_host: # Verify if the option host import is enabled
		for obj in import_objects(list_object): # Import file with object in list
			create_iphost(obj.keys()[0], obj.values()[0])
