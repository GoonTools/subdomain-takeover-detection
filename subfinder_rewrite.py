import re
import requests
from itertools import repeat, chain
from multiprocessing import Pool

SOURCES = [
		"https://otx.alienvault.com/api/v1/indicators/domain/$/passive_dns",
		"https://jldc.me/anubis/subdomains/$",
		"https://dns.bufferover.run/dns?q=.$",
		"https://tls.bufferover.run/dns?q=.$",
		"https://api.certspotter.com/v1/issuances?domain=$&include_subdomains=true&expand=dns_names",
		"https://crt.sh/?q=%.$",
		"http://api.hackertarget.com/hostsearch/?q=$",
		"https://rapiddns.io/subdomain/$",
		"https://riddler.io/search?q=pld:$&view_type=data_table",
		"https://sonar.omnisint.io/subdomains/$?page=",
		"https://api.sublist3r.com/search.php?domain=$",
		"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$",
		"https://api.threatminer.org/v2/domain.php?q=$&rt=5",
		"http://web.archive.org/cdx/search/cdx?url=*.$/*&output=txt&fl=original&collapse=urlkey"
	  ]

def send_requests(source, domain):
	try:
		response = requests.get(source, timeout=3)

	except requests.exceptions.Timeout as e:
		return []

	#get subdomains from response
	pattern = "[a-z0-9_.-]+\." + domain
	subdomains = re.findall(pattern, response.text)

	#remove duplicates
	return list(set(subdomains))


def subfinder(domain):
	#update source list with domain
	sources = [source.replace("$", domain) for source in SOURCES]

	#send requests
	with Pool(processes=14) as pool:
		results = pool.starmap(send_requests, zip(sources, repeat(domain)))

	#combine lists and remove duplicates
	subdomains = list(set(chain.from_iterable(results)))
	return subdomains