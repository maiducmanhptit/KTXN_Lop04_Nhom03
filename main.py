import json
import requests
import time
import urllib3
from dotenv import load_dotenv
import os

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def cleanup():
    # Delete the scan
    dummy = requests.delete(url + '/scans/' + scan_id, headers=request_header, verify=False)
    # Delete the target
    dummy = requests.delete(url + '/targets/' + target_id, headers=request_header, verify=False)

# Declare variables
url = f"https://{os.getenv('HOST')}:{os.getenv('PORT')}/api/v1"
api = os.getenv('API')
target_url = "http://testphp.vulnweb.com/"
target_description = "Test PHP Site - created via ax-python-api.py"
fullscan_profile_id = "11111111-1111-1111-1111-111111111111"
request_header = {'X-Auth': api, 'Content-Type': 'application/json'}

# Create our intended target - target ID is in the JSON response
request_body = {"address": target_url, "description": target_description, "type": "default", "criticality": 10}
target_id_response = requests.post(url + '/targets', json=request_body, headers=request_header, verify=False)
target_id_json = json.loads(target_id_response.content)
target_id = target_id_json["target_id"]

# Trigger a scan on the target - scan ID is in the HTTP response headers
request_body = {
    "profile_id": fullscan_profile_id,
    "incremental": False,
    "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
    "user_authorized_to_scan": "yes",
    "target_id": target_id
}

scan_id_response = requests.post(url + '/scans', json=request_body, headers=request_header, verify=False)
scan_id = scan_id_response.headers["Location"].replace("/api/v1/scans/", "")

LoopCondition = True
while LoopCondition:
    scanstatus_response = requests.get(url + '/scans/' + scan_id, headers=request_header, verify=False)
    scan_status_json = json.loads(scanstatus_response.content)
    scan_status = scan_status_json["current_session"]["status"]
    if scan_status == "processing":
        print("Scan Status: Processing - waiting 30 seconds...")
    elif scan_status == "scheduled":
        print("Scan Status: Scheduled - waiting 30 seconds...")
    elif scan_status == "completed":
        LoopCondition = False
    elif scan_status == "failed":
        print("Scan Status: Failed - Aborting")
        cleanup()
        exit()
    else:
        print("Invalid Scan Status: Aborting")
        cleanup()
        exit()
    time.sleep(30)

# Obtain the scan session ID
scan_session_response = requests.get(url + '/scans/' + scan_id, headers=request_header, verify=False)
scan_session_json = json.loads(scan_session_response.content)
scan_session_id = scan_session_json["current_session"]["scan_session_id"]

# Obtain the scan result ID
scan_result_response = requests.get(url + '/scans/' + scan_id + "/results", headers=request_header, verify=False)
scan_result_json = json.loads(scan_result_response.content)
scan_result_id = scan_result_json["results"][0]["result_id"]

# Obtain scan vulnerabilities
scan_vulns_response = requests.get(url + '/scans/' + scan_id + '/results/' + scan_result_id + '/vulnerabilities',
                                             headers=request_header, verify=False)

# Phân tích chuỗi JSON và hiển thị thông tin chi tiết về các lỗ hổng
parsed_data = json.loads(scan_vulns_response.content)
vulnerabilities = parsed_data['vulnerabilities']

print("Scan Vulnerabilities")
print("====================")
print("")

for vuln in vulnerabilities:
    print(f"Vulnerability ID: {vuln['vuln_id']}")
    print(f"Severity: {vuln['severity']}")
    print(f"Criticality: {vuln['criticality']}")
    print(f"URL: {vuln['affects_url']}")
    print(f"Detail: {vuln['affects_detail']}")
    print(f"Tags: {', '.join(vuln['tags'])}")
    print(f"Status: {vuln['status']}")
    print(f"Last Updated: {vuln['vt_updated']}")
    print("====================")
    print("")
