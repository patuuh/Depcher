import os
import json
from Wappalyzer import Wappalyzer, WebPage

# Targets refreshed hourly: https://github.com/arkadiyt/bounty-targets-data.git

''' TO DO:
- ANALYZE WITH SNYK(?) THE WAPPALYZER DATA
'''

if os.path.isfile('bounty-targets-data'):
    os.system('git clone https://github.com/arkadiyt/bounty-targets-data.git')
else:
    os.system('cd bounty-targets-data && git pull')

wappalyzer = Wappalyzer.latest()

targets_json = open("bounty-targets-data/data/hackerone_data.json", "r")
targets = json.load(targets_json)
file_to_save = open("versions.txt","w+")

for target in targets:
    name = target['name']
    file_to_save.write(name + "\n---------------\n")
    for target_url in target['targets']['in_scope']:
        asset_type = target_url['asset_type']
        if 'URL' not in asset_type:
            continue
        url = target_url['asset_identifier']
        if '*' in url:
             continue
        if 'http' not in url:
             url = "https://" + url
             
        print("Analyzing " + url + " ...")
        webpage = WebPage.new_from_url(url)
        results = wappalyzer.analyze_with_versions(webpage)
        file_to_save.write(url + "\n")
        for result in results:
            version = results[result]['versions']
            app = result
            if '[]' in str(version):
                 continue
            file_to_save.write(app + ": " + str(version) + "\n")
    file_to_save.write(name + "\n")
            


