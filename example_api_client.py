import requests
import datetime
import urllib3
from warpcore.engineering import WarpCore

urllib3.disable_warnings()  # Used just for testing to silence the self-signed cert warning

server_uri = "https://127.0.0.1"

# Example: looking up a company unique SEC identifier (CIK)
payload = {"lookup": "apple"}
response = requests.post(f"{server_uri}/cik", json=payload, verify=False)
result = response.json()

# Example: looking up data available on a NIST NVD CVE ID
payload = {"lookup": "CVE-2019-0708"}
response = requests.post(f"{server_uri}/cve", json=payload, verify=False)
result = response.json()


# Example: Updating the database
# payload = {"key": "change_me"}
response = requests.post(f"{server_uri}/server", json=payload, verify=False)
result = response.json()

# Example: Scoring an asset owned by "Apple" with certain vulnerabilities
payload = {
    "cves": ["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0880", "CVE-2021-22721"],
    "company": "apple",
}
response = requests.post(f"{server_uri}/score", json=payload, verify=False)
result = response.json()


# Example: Scoring an asset owned by Apple Inc. (CIK: 320193) with certain vulnerabilities
payload = {
    "cves": ["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0880", "CVE-2021-22721"],
    "company": 320193,
}
response = requests.post(f"{server_uri}/score", json=payload, verify=False)
result = response.json()


# Example: Scoring an organization with separate devices which have Inntinn scores of 22, 15, 99, 5
payload = {
    "scores": [22, 15, 99, 5],
}
response = requests.post(f"{server_uri}/score/org", json=payload, verify=False)
result = response.json()


# Example: Speed test


def worker(job):
    response = requests.post(f"{server_uri}/score", json=job, verify=False)


payload = {
    "cves": ["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0880", "CVE-2021-22721"],
    "company": 320193,
}
jobs = []
intervals = 100
for _ in range(intervals):
    jobs.append(payload)  # Just building a list of jobs for multi-threading
print(
    "Be aware that running the API on Windows is not recommended as it does not allow multi-threading"
)
print("Running benchmark...")
start = datetime.datetime.now()
WarpCore().list_engage(jobs, worker)  # https://github.com/BlackburnHax/warpcore
stop = datetime.datetime.now()

delta = stop - start
per_second = delta.seconds / intervals
print(f"{per_second} per second")
