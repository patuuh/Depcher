import requests
import json
import datetime
import os
import sys
import platform
import configparser
import argparse

now = datetime.datetime.now()
time = now.strftime("%d%b_%H%M")
config = configparser.ConfigParser()
config.read("config.conf")
h1Key = config.get("API", "h1_api")
h1User = config.get("API", "h1_user")

if h1Key == "ENTER API KEY HERE":
        raise Exception(
            "You need to add H1 API key before starting the scan")

def targets(page):

    headers = {
    'Accept': 'application/json'
    }

    response = requests.get(
    'https://api.hackerone.com/v1/hackers/programs?page[number]=%s&page[size]=100' % page,
    auth=(h1User, h1Key),
    headers = headers
    )

    json_response = response.json()
    data = json_response['data']
    for item in data:
        handle = item['attributes']['handle']
        name = item['attributes']['name']

    return data

def detailed_target_info(handle):
    headers = {
    'Accept': 'application/json'
    }

    response = requests.get(
    'https://api.hackerone.com/v1/hackers/programs/%s' % handle,
    auth=(h1User, h1Key),
    headers = headers
    )

    data = response.json()
    #data = json_response['data']
    '''
    bounty = data['attributes']['offers_bounties']
    targets = data['relationships']['structured_scopes']['data']
    for target in targets:
        url = target['attributes']['asset_identifier']
    '''
    return data

if __name__ == '__main__':

    if sys.version_info[0] < 3:
        raise Exception("You need to use Python3")

    if h1Key == "ENTER API KEY HERE":
        raise Exception(
            "You need to add H1 API key before starting the scan")
    
    targets(1)
