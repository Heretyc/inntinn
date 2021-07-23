import inntinn
import pathlib  # Needed only for this example, we use db to obtain the configuration file location

db = inntinn.Database(
    pathlib.Path.cwd() / "config.json", tls=False
)  # tls=False only used for testing... we hope you are not running a production MongoDB without TLS!

db.update()  # This should be performed at least once per week to maintain the most current data, but can be done as much as daily

blue_keep = db.cve_lookup("CVE-2019-0708")
print(blue_keep)
apples = db.cik_lookup("apple")  # When the CIK is unknown for a company
for key, value in apples.items():
    print(f"CIK: {key} = {value}")

apple = db.score_device("CVE-2019-0708", 320193)
noname = db.score_device_fuzzy("cve-2019-0708", "some non-existent company")
a = db.score_device_fuzzy("CVE-2019-0708", "American Airlines")
b = db.score_device("CVE-2019-0708", 4515)
c = db.score_device("CVE-1999-0019", 1810019)
d = db.score_device("CVE-2018-0880", 6176)
e = db.score_device("CVE-2019-0708", "4515")
f = db.score_device_list(
    ["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0880", "CVE-2021-22721"], 4515
)  # The preferred method to score devices, this function creates an intelligent score based on standard deviation
# PLEASE NOTE: This function is not merely adding up individual vuln scores, so be sure to use db when evaluating a devices total risk
g = db.score_device_list_fuzzy(
    [
        "CVE-2019-0708",
        "CVE-1999-0019",
        "CVE-2018-0840",
        "CVE-2021-22721",
        "CVE-2021-3619",
    ],
    "Ampco Pittsburgh",
)  # This is the fallback method for score_device_list() when the company CIK is unknown or unavailable
org_a_metrics = [
    a[
        0
    ],  # Slicing is needed here as "fuzzy" matches return tuples in the form (score,confidence)
    b,
    e,
    f,  # Ideally, every score in here should be calculated using score_device_list() or its _fuzzy() equivalent
    # but, we will assume a,b,e just have a single vulnerability
]

org_b_metrics = [d, g[0]]

org_a_score = db.score_org(org_a_metrics)
org_b_score = db.score_org(org_b_metrics)
print(f"Org A score = {org_a_score} , Org B score = {org_b_score}")
