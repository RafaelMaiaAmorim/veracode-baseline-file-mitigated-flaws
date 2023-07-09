import argparse
import sys
import requests
import json
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

api_base = "https://api.veracode.com/"
headers = {"User-Agent": "Python HMAC"}


def GenerateBaseLineFile(id, key, app_name, baseline_file):
    app_guid = GetApplicationGUID(id, key, app_name)
    flawsData = GetApplicationMitigatedFlaws(id, key, app_guid)
    CompareFlaws(flawsData, baseline_file)

def GetApplicationGUID(id, key, app_name):
    app_guid = ""
    response = requests.get(api_base + "appsec/v1/applications/?name=" + app_name, auth=RequestsAuthPluginVeracodeHMAC(id, key), headers=headers)
    
    if response.status_code == 200:
        print("Application GUID OK.")
        data = response.json()

        if data["_embedded"] is not None:
            app_guid = data["_embedded"]["applications"][0]["guid"]
            print("Application found GUID = " + app_guid)
        else:
            print(f"Application Name not found. Error: {response.text}")
    else:
        print("API Error.")
    return app_guid

def GetApplicationMitigatedFlaws(id, key, app_guid):
    flawsData = ""
    response = requests.get(api_base + "appsec/v2/applications/" + app_guid + "/findings?scan_type=STATIC", auth=RequestsAuthPluginVeracodeHMAC(id, key), headers=headers)
    
    if response.status_code == 200:
        print("Application Flaws OK.")
        flawsData = response.json()
        print(flawsData)
        
    else:
        print("API Error.")
    
    return flawsData

def CompareFlaws(flaws_data, baseline_file):

    approved_findings = []
    mitigated_flaws = []

    with open(baseline_file, 'r') as f1:
        base_data = json.load(f1)

    for finding in flaws_data['_embedded']['findings']:
        if finding.get('finding_status', {}).get('resolution_status') == "APPROVED":
            approved_findings.append(finding)

    for finding in approved_findings:
        approved_file_name = finding.get('finding_details', {}).get('file_name')
        approved_line_number = finding.get('finding_details', {}).get('file_line_number')
        approved_qualified_function_name = finding.get('finding_details', {}).get('procedure')
        approved_attack_vector = finding.get('finding_details', {}).get('attack_vector')

        for base_finding in base_data['findings']:
            base_file_name = base_finding.get('files', {}).get('source_file', {}).get('file')
            base_line_number = base_finding.get('files', {}).get('source_file', {}).get('line')
            base_qualified_function_name = base_finding.get('files', {}).get('source_file', {}).get('qualified_function_name')
            base_attack_vector = base_finding.get('title')

            if approved_file_name in base_file_name and approved_line_number == base_line_number and approved_qualified_function_name == base_qualified_function_name and approved_attack_vector == base_attack_vector:
                mitigated_flaws.append(base_finding)

    base_data['findings'] = mitigated_flaws
    with open('Baseline_Mitigated_Result.json', 'w') as output_file:
        json.dump(base_data, output_file, indent=4)

parser = argparse.ArgumentParser()

parser.add_argument('-ID', '--id', required=True, help='ID')
parser.add_argument('-key', '--key', required=True, help='Key')
parser.add_argument('-app', '--application', dest='app_name', required=True, help='Application Name')
parser.add_argument('-baseline', '--baseline-file', dest='baseline_file', required=True, help='Baseline File')

args = parser.parse_args()

id = args.id
key = args.key
app_name = args.app_name
baseline_file = args.baseline_file

if not all([id, key, app_name, baseline_file]):
    parser.print_usage()
    sys.exit(1)

GenerateBaseLineFile(id, key, app_name, baseline_file)
