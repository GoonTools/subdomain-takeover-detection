import sys
import fastdns
import requests
from multiprocessing import Pool
from subfinder_rewrite import subfinder

fingerprints = {
		"Agile CRM": "Sorry, this page is no longer available.",
		"Anima": "If this is your website and you've just created it, try refreshing in a minute",
		"AWS/S3": "The specified bucket does not exist",
		"Bitbucket": "Repository not found",
		"Campaign Monitor": "'Trying to access your account?'",
		"Digital Ocean": "Domain uses DO name serves with no records in DO.",
		"Fastly": "Fastly error: unknown domain:",
		"Feedpress": "The feed has not been found.",
		"Ghost": "The thing you were looking for is no longer here, or never was",
		"Github": "There isn't a Github Pages site here.",
		"HatenaBlog": "404 Blog is not found",
		"Help Juice": "We could not find what you're looking for.",
		"Help Scout": "No settings were found for this company:",
		"Heroku": "No such app",
		"Intercom": "Uh oh. That page doesn't exist.",
		"JetBrains": "is not a registered InCloud YouTrack",
		"Kinsta": "No Site For Domain",
		"LaunchRock": "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",
		"Mashery": "Unrecognized domain",
		"Ngrok": "Tunnel *.ngrok.io not found",
		"Pantheon": "404 error unknown site!",
		"Pingdom": "Sorry, couldn't find the status page",
		"Readme.io": "Project doesnt exist... yet!",
		"Shopify": "Sorry, this shop is currently unavailable.",
		"SmartJobBoard": "This job board website is either expired or its domain name is invalid.",
		"Surge.sh": "project not found",
		"Tumblr": "Whatever you were looking for doesn't currently exist at this address",
		"Tilda": "Please renew your subscription",
		"Uberflip": "Non-hub domain, The URL you've accessed does not provide a hub.",
		"UserVoice": "This UserVoice subdomain is currently available!",
		"Wordpress": "Do you want to register ",
		"Worksites": "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist."
	}

def fingerprint_domain(domain):
	try: response = requests.get(f"http://{domain}",  timeout=3)
	except: pass

	try: response = requests.get(f"https://{domain}", timeout=3)
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