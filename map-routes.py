
import awsipranges
import dns.resolver
import re
import requests
import sys
import socket
import argparse

from bs4 import BeautifulSoup
from tabulate import tabulate

aws_ip_ranges = awsipranges.get_ranges()
MISC_ROUTES_IPv4 = set()

def checkValid(ASN):
	URL = f"https://bgp.he.net/{ASN}"
	response = requests.get(URL)
	if "Average AS Path Length (all): 0.000" in response.text:
		return False
	else:
		return True


def filterASN(ASN_LIST):
	VALID_ASN_LIST = set()
	for asn in ASN_LIST:
		if checkValid(asn):
			VALID_ASN_LIST.add(asn)
	print(f"Number of valid ASNs: {len(VALID_ASN_LIST)}")
	return VALID_ASN_LIST


def getRoutesInfo(routes):
	URL = f"https://bgp.he.net/super-lg/report/api/v1/whois/prefixes"
	data = {"prefixes": routes}
	response = requests.post(URL, json = data)
	prefixes = response.json()["response"]
	final_list = []
	for prefix in prefixes:
		route = prefix["Prefix"]
		#Collecting only for IPv4
		if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|1[0-9]|2[0-9]|3[0-2])$", route):
			isValid = not prefix["bogondata"]["isbogon"]
			status = prefix["bogondata"]["status"]
			country = prefix["countrydata"]["Iso3166_Name"]
			if "Org" in prefix:
				org = prefix["Org"]
				prefix_details = [route, country, org, status, isValid]
				final_list.append(prefix_details)
			else:
				prefix_details = [route, country, "", status, isValid]
				final_list.append(prefix_details)
	return final_list


def collectRoutesFromASN(ASN):
	ASN = ASN[2:]
	URL = f"https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{ASN}"
	response = requests.get(URL)
	prefixes = response.json()["prefixes"]
	pref_list = []
	for prefix in prefixes:
		pref_list.append(prefix["Prefix"])
	return getRoutesInfo(pref_list)


def getRouteForIP(IP):
	URL = f"https://bgp.he.net/super-lg/api/v1/show/bgp/route/{IP}?match-asn=&match-type=all&search-type=exact&match-neighbor="
	response = requests.get(URL)
	if len(response.json()["prefixes"]) > 0:
		route = response.json()["prefixes"]
		valid_asn = response.json()["response"][0]["rpki"]["response"]["validated_route"]["route"]["origin_asn"][2:]
		details = response.json()["response"][0]["asnmap"][valid_asn]
		return route, details
	else:
		return IP
	
			
def collectASNs(table_rows):
	ASN_LIST = set()
	IPV4_ROUTE_LIST = set()
	for table_row in table_rows:
		columns = table_row.find_all('td')
		if len(columns) == 0:
			continue
		
		if columns[1].text == "ASN":
			ASN_LIST.add(columns[0].text)
		'''
		if columns[1].text == "Route":
			if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|1[0-9]|2[0-9]|3[0-2])$", columns[0].a.text):
				MISC_ROUTES_IPv4.add(columns[0].a.text)
		'''
	return filterASN(ASN_LIST)
	
def processASN(ASN):
	print(f"Collecting routes for ASN: {ASN}")
	routes = collectRoutesFromASN(ASN)
	return routes

def dumpRoutesforASN(routes):
	print(tabulate(routes, headers = ["Route", "Country", "Org", "Status", "isValid"]))
	print()
	
def dumpInfoForIP(details):
	details = list(details.values())
	print(tabulate(([details]), headers = ["ASN", "COUNTRY", "DESC", "ORG", "ROUTE"]))
	print()
	
def dumpASNs(ASNs):
	for asn in ASNs:
		print(asn)
		
def getRawASNs(company):
	URL = f"https://bgp.he.net/search?search[search]={company}&commit=Search"
	response = requests.get(URL)
	soup = BeautifulSoup(response.text, 'html.parser')
	initial_table = soup.find('table')
	table_rows = initial_table.find_all('tr')
	return collectASNs(table_rows)
	
def resolve(domain):
	answers = dns.resolver.resolve(domain, 'A')
	temp = str(answers.rrset).split()
	IPs = []
	for i in range(4, len(temp), 5):
		IPs.append(temp[i])
	return IPs
	

def cmdASN(args):
	if args.company:
		ASNs = getRawASNs(args.company)
		dumpASNs(ASNs)
	
def cmdPrefix(args):
	if args.ASN:
		routes = processASN(args.ASN)
		dumpRoutesforASN(routes)
		
def cmdResolve(args):
	IPtoRoute = {}
	if args.domain:
		IPs = resolve(args.domain)
		[print(ip) for ip in IPs]
		
def cmdIP(args):
	if args.address:
		route, details = getRouteForIP(args.address)
		details['Route'] = route[0]
		if type(route) is not str: 
			#dumpRoutesforASN(getRoutesInfo(route))
			dumpInfoForIP(details)
		else:
			print(route)

def checkIPinAWSRange(IP):
	if IP in aws_ip_ranges:
		return aws_ip_ranges[IP]
	
	
def cmdAWS(args):
	if args.address:
		info = checkIPinAWSRange(args.address)
		if info:
			print(f"{args.address} found in AWS range")
			print(f"Route: {info}") 
			print(f"Region: {info.region}")
			print(f"Services: {info.services}")
		else:
			print(f"{args.address} not found in AWS range")
		
def main():
	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers()
	
	command_ASN = subparsers.add_parser("ASN")
	command_ASN.add_argument("company", help = "ASNs for the company")
	command_ASN.set_defaults(func = cmdASN)
	
	command_PREFIXES = subparsers.add_parser("prefixes")
	command_PREFIXES.add_argument("ASN", help = "Prefixes for the ASN")
	command_PREFIXES.set_defaults(func = cmdPrefix)
	
	command_RESOLVE = subparsers.add_parser("resolve")
	command_RESOLVE.add_argument("domain", help = "Domain to be resolved")
	command_RESOLVE.set_defaults(func = cmdResolve)
	
	command_IP = subparsers.add_parser("IP")
	command_IP.add_argument("address", help = "address to fetch info for")
	command_IP.set_defaults(func = cmdIP)
	
	command_AWS = subparsers.add_parser("AWS")
	command_AWS.add_argument("address", help = "IP to search for in AWS ranges")
	command_AWS.set_defaults(func = cmdAWS)



	args = parser.parse_args()

	try:
		args.func(args)
		
	except AttributeError as e:
		parser.print_help()
		#print(e)
		
	except Exception as e:
		print(e)
	
		
		
	
	
main()
