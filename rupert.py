import sys
import json
import fastdns
import requests
from multiprocessing import Pool
from subfinder_rewrite import subfinder

FINGERPRINTS_FILE = "fingerprints.json
f = open(FINGERPRINTS_FILE, 'r')
fingerprints = json.loads(f.read())

def fingerprint_domain(domain):
	for url in [f"http://{domain}", f"https://{domain}"]:
		try: 
			response = requests.get(url,  timeout=3)
			break
		except: return
		
	for service in fingerprints:
		fingerprint = fingerprints[service]
		
		if fingerprint in response.text:
			return (domain, service)


def is_hijackable(domain):
	subdomains = subfinder(domain)
	subdomains_with_cnames = fastdns.bulk_resolve_domains(subdomains)

	#send requests
	with Pool(processes=30) as pool:
		results = pool.map(fingerprint_domain, subdomains_with_cnames)

	#combine lists and remove duplicates
	vulnerable_domains = [x for x in list(set(results)) if x]
	return vulnerable_domains


if len(sys.argv) == 2:
	for result in is_hijackable(sys.argv[1]):
		domain, service = result[0], result[1]
		whitespace = " " * (35 - len(domain))
		print(domain, whitespace, service)
