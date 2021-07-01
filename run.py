import os
import json
import sys
import configparser
import datetime
import argparse
import vulners
from Wappalyzer import Wappalyzer, WebPage

# Targets refreshed hourly: https://github.com/arkadiyt/bounty-targets-data.git

now = datetime.datetime.now()
time = now.strftime("%d%b_%H%M")
config = configparser.ConfigParser()
config.read("config.conf")
vulner = config.get("Misc", "vulners")
VulnersKey = config.get("API", "Vulners_api")

def scan():
	
	wappalyzer = Wappalyzer.latest()
	targets_json = open("bounty-targets-data/data/hackerone_data.json", "r")
	targets = json.load(targets_json)
	
	filepath =  "reports/%s/" % (time)
	file_to_save_targets = open(filepath + "versions.txt","w+")
	vulners_file_save = open(filepath + "vulners.txt","w+")

	version_list = ""

	for target in targets:
		try:
			name = target['name']
			file_to_save_targets.write(name + "\n---------------\n")
			vulners_file_save.write(name + "\n---------------\n")
			for target_url in target['targets']['in_scope']:
				asset_type = target_url['asset_type']
				if 'URL' not in asset_type:
					continue
				url = target_url['asset_identifier']
				if '*' in url or ',' in url: # TODO CHANGE THIS ',' to actually split multiple target urls
					 continue
				if 'http' not in url:
					if args.force:
						url = "http://" + url
					else:
						url = "https://" + url
					 
				print("Analyzing " + url + " ...")
				
				try:
					webpage = WebPage.new_from_url(url)
					results = wappalyzer.analyze_with_versions(webpage)
				except Exception:
					print("Following url failed for some reason: " + url)
				
				file_to_save_targets.write("--" + url + "\n")
				vulners_file_save.write("--" + url + "\n")
				for result in results:
					versions = results[result]['versions']
					app = result
					if '[]' in str(versions):
						 continue
					for version in versions:
						file_to_save_targets.write("----" + app + ": " + str(version) + "\n")
						
						vulners_query = app + " " + str(version)
						if vulners_query not in version_list:
							version_list = version_list + "," + str(vulners_query)
						vulners_api = vulners.Vulners(api_key=VulnersKey) # Fetch vulnerabilites from Vulners.com API 
						vulner_results = vulners_api.softwareVulnerabilities(app, str(version)) # Search for the public available exploits
						exploit_list = vulner_results.get('exploit')
						vulnerabilities_list = [vulner_results.get(key) for key in vulner_results if key not in ['info', 'blog', 'bugbounty']]
						# vulner_results = vulners_api.search(vulners_query)
						if len(vulnerabilities_list) != 0:
							vulners_file_save.write("------ " + str(vulners_query) + " ------ \n")
							for vulns in vulnerabilities_list:
								for vuln in vulns:
									vulners_file_save.write(str(vuln['title']) + " ---- "+ str(vuln['href']))
									vulners_file_save.write("\n----\n")
						vulners_file_save.write("----------------------------\n\n")
			file_to_save_targets.write("###################\n\n")
			vulners_file_save.write("###################\n\n")
		except KeyboardInterrupt:
			print("Keyboard interrupt detected. Finishing up...")
			break
	
	file_to_save_targets.write("----------- All versions found: --------\n")
	split_version_list = sorted(version_list.split(","))
	for ver in split_version_list:
		file_to_save_targets.write(ver + "\n")
		

def scan_solo(targets):

	targets = targets.split(",")
	filepath =  "reports/%s/" % (time)
	file_to_save_targets = open(filepath + "versions.txt","w+")
	vulners_file_save = open(filepath + "vulners.txt","w+")
	
	version_list = ""

	for target in targets:
		results = ""
		try:
			file_to_save_targets.write(target + "\n---------------\n")
			vulners_file_save.write(target + "\n---------------\n")
			if 'http' not in target:
				if args.force:
					url = "http://" + target
				else:
					url = "https://" + target
			print("Analyzing " + url + " ...")
				
			try:
				webpage = WebPage.new_from_url(url)
				results = wappalyzer.analyze_with_versions(webpage)
			except Exception:
				print("Following url failed for some reason: " + url)
			if results == "":
				continue
				
			for result in results:
					versions = results[result]['versions']
					app = result
					if '[]' in str(versions):
						 continue
					for version in versions:
						file_to_save_targets.write("----" + app + ": " + str(version) + "\n")
						
						vulners_query = app + " " + str(version)
						if vulners_query not in version_list:
							version_list = version_list + "," + str(vulners_query)
						vulners_api = vulners.Vulners(api_key=VulnersKey) # Fetch vulnerabilites from Vulners.com API 
						vulner_results = vulners_api.softwareVulnerabilities(app, str(version)) # Search for the public available exploits
						exploit_list = vulner_results.get('exploit')
						vulnerabilities_list = [vulner_results.get(key) for key in vulner_results if key not in ['info', 'blog', 'bugbounty']]
						# vulner_results = vulners_api.search(vulners_query)
						if len(vulnerabilities_list) != 0:
							vulners_file_save.write("------ " + str(vulners_query) + " ------ \n")
							for vulns in vulnerabilities_list:
								for vuln in vulns:
									vulners_file_save.write(str(vuln['title']) + " ---- "+ str(vuln['href']))
									vulners_file_save.write("\n----\n")
						vulners_file_save.write("----------------------------\n\n")
			file_to_save_targets.write("###################\n\n")
			vulners_file_save.write("###################\n\n")
		except KeyboardInterrupt:
			print("Keyboard interrupt detected. Finishing up...")
			break
			
			
if __name__=='__main__':

	if sys.version_info[0] < 3:
		raise Exception("You need to use Python3")

	parser = argparse.ArgumentParser(description='Web scan tool', usage='%(prog)s [options]')
	parser.add_argument('-H', '--host', dest="host", help='Specific host(s) to scan instead of a list of hosts. Separated with ","')
	parser.add_argument('-f', '--force', dest="force", default=False, action='store_true', help='Force scanning to HTTP instead of HTTPS')
	args = parser.parse_args()

	api_key = config.get("API", "Vulners_api")  
	if api_key == "ENTER API KEY HERE" and vulner == "1":
		raise Exception("You need to add Vulners API key before starting the scan with Vulners DB")
		
	if os.path.isfile('bounty-targets-data'):
		os.system('git clone https://github.com/arkadiyt/bounty-targets-data.git')
	else:
		os.system('cd bounty-targets-data && git pull')
	os.system("mkdir -p reports/%s" % (time))
	
	if args.host:
		scan_solo(args.host)
	else:
		scan()


