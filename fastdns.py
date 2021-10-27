import dns.resolver
from multiprocessing import Pool

dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8']

def resolve_domain(domain):
	try:
		answers = dns.resolver.query(domain, 'CNAME')
		return domain
		
	except:
		return False


def bulk_resolve_domains(subdomains):
	p = Pool(processes=100)
	results = p.map(resolve_domain, subdomains)
	p.close()
	p.terminate()

	return [x for x in list(set(results)) if x]