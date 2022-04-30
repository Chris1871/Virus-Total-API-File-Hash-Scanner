#!/usr/bin/env python3

import argparse
import requests
import re

def verify_hash(file_hash):

  # Check for SHA256 Hash
  if re.findall("^[0-9a-f]{64}$",file_hash,re.IGNORECASE):
    return file_hash
  # Check for MD5 Hash
  elif re.findall("^[0-9a-f]{32}$",file_hash,re.IGNORECASE):
    return file_hash
  # Bad Hash
  else:
    print("You have entered in an invalid hash.  Please enter an MD5 or SHA256 hash and try again.")
    
def run():
  # Arguements: will need to enter an API Key and File Hash
  parser = argparse.ArgumentParser("Enter in the MD5 or SHA256 hash of the file for Virus Total to scan")
  parser.add_argument('-H','--file_hash', type=verify_hash, required=True, help='Enter the MD5 or SHA256 hash of the file for Virus Total to scan')
  parser.add_argument('-A','--api_key', required=True, help='Enter your API Key for Virus Total')
  args = parser.parse_args()

  # Only fetch results if the user entered an api key and valid hash
  if args.file_hash and args.api_key:
    fetch_results(args.api_key,args.file_hash)

def fetch_results(api_key, file_hash):
  params = {'apikey': api_key, 'resource': file_hash}
  url = 'https://www.virustotal.com/vtapi/v2/file/report'
  response = requests.get(url, params=params)

  print()
  print(str(response))
  # If status code is 200, continue
  if str(response) == '<Response [200]>':
    json_response = response.json()

    # If vt_response equals 0, file was NOT found in VT, end here
    vt_response = int(json_response.get('response_code'))
    if vt_response == 0:
      print('[+] This File is clean')

    # If vt_response equals 1, the hash was found in VT, now check for malicious positives
    elif vt_response == 1:
      vt_detected_positives = int(json_response.get('positives'))
      if vt_detected_positives > 5:
        print(f'[+] This is a Malicious File.  {vt_detected_positives} AV Engines have flagged this file as Malicious.')
      elif 1 <= vt_detected_positives <= 5:
        print(f'[+] This may be a Malicious File.  {vt_detected_positives} AV Engines have flagged this file as Malicious.')
      else:
        print('This File is clean.')

  # If status code is not 200, end and inform client of failure     
  else:
    print('[-] The API call has failed.  Please verify your API key and try again.')

# Run the Scan
run()
