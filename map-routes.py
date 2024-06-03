import re
import requests
import sys
from bs4 import BeautifulSoup
from tabulate import tabulate

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
	return VALID_ASN_LIST

def collectASNAndRoutes(table_rows):
	ASN_LIST = set()
	IPV4_ROUTE_LIST = set()
	for table_row in table_rows:
		columns = table_row.find_all('td')
		if len(columns) == 0:
			continue
		
		if columns[1].text == "ASN":
			ASN_LIST.add(columns[0].text)
		
		if columns[1].text == "Route":
			if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|1[0-9]|2[0-9]|3[0-2])$", columns[0].a.text):
				MISC_ROUTES_IPv4.add(columns[0].a.text)
	
	return filterASN(ASN_LIST)

def collectRoutesFromASN(ASN):
	ASN = ASN[2:]
	URL1 = f"https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{ASN}"
	URL2 = f"https://bgp.he.net/super-lg/report/api/v1/whois/prefixes"
	response = requests.get(URL1)
	prefixes = response.json()["prefixes"]
	pref_list = []
	for prefix in prefixes:
		pref_list.append(prefix["Prefix"])
	data = {"prefixes": pref_list}
	response = requests.post(URL2, json = data)
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

def getRawData(URL):
	response = requests.get(URL)
	soup = BeautifulSoup(response.text, 'html.parser')
	initial_table = soup.find('table')
	table_rows = initial_table.find_all('tr')
	return collectASNAndRoutes(table_rows)

def main():
	company = sys.argv[1]
	URL = f"https://bgp.he.net/search?search[search]={company}&commit=Search"
	ASNs = getRawData(URL)
	print(f"Number of Valid ASNS identified: {len(ASNs)}")
	print()
	for asn in ASNs:
		print(f"Collecting routes for ASN: {asn}")
		print(tabulate(collectRoutesFromASN(asn), headers = ["Route", "Country", "Org", "Status", "isValid"]))
		print()
	
	'''	
	print("MISC Routes: ")
	misc = list(MISC_ROUTES_IPv4)
	print(tabulate(getRoutesInfo(misc), headers = ["Route", "Country", "Org", "Status", "isValid"]))
	'''
main()
