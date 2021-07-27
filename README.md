[![Inntinn: Intelligence](https://github.com/BlackburnHax/inntinn/raw/main/docs/logo.png)](https://github.com/BlackburnHax/inntinn)

# inntinn 
[![API Documentation: Swagger](https://img.shields.io/badge/API%20Docs-Swagger-blue)](https://bhax.net/api) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black) [![pypi](https://img.shields.io/pypi/v/inntinn.svg)](https://pypi.org/project/inntinn/) [![wheel](https://img.shields.io/pypi/wheel/inntinn.svg)](https://pypi.org/project/inntinn/)
> OSINT composite vulnerability database.

_Inntinn - Scotts Gaelic for "Intelligence"_

**Inntinn has one primary objective: simplify the process of communicating risk to stakeholders and measuring risk over time in a concise manner.**

Acknowledging that threat-actors perform reconnaissance and go for “low hanging fruit”, Inntinn aims to model this behavior in order to generate a single number that can be used as a consistent benchmark even among dissimilar organizations.


Scores are based on metrics that more threat-actors are using to date: target company valuation, vulnerabilities they are actually aware of, and vulnerabilities that are most likely to work. 

**To put it another way**: Gross Company Assets, Vulnerability Notoriety, and the damage or ease of use on a vulnerability.

## Inntinn Scores
There are 2 forms of scoring, Per Device and Per Organization.

- The **Per Device** score is calculated using a list of all CVE’s (vulnerabilities) that a device is vulnerable to, and the company which owns it. (If the company is not publicly traded, the lowest score metric is used to communicate that the organization is not a primary target of attackers globally)
- The **Per Organization** score only needs the summation of all organizational Inntinn **Per Device** scores. This can be used as a “Per Department”, “Per Datacenter” or any other organizational unit including the company as a whole.


### Per Device
The “Per Device” score represents the cumulative risk posed by a single device within an organization.

The guiding principles behind this score are:

1) Rather than using a complex metric, we boil-down the score into a simple 1-100 percentage. (_100% = highest risk_)

2) Risk is updated as threats evolve over time. Inntinn pulls directly from the NIST National Vulnerability Database, updating as CVE’s change in scope over time. As a vulnerability grows in notoriety, so does the score.

3) As new PoCs (Proof of Concept code) are added to the ExploitDB, scores are dynamically adjusted to account for greater likelihood of exploitation.

4) Finally, scoring is based on public financial fillings with the Securities and Exchange Commission (SEC). Base scores for companies curve sharply upward as we look at the most profitable companies.


![Score Distribution](https://github.com/BlackburnHax/inntinn/raw/main/docs/score-dist.png)

### Per Organization
- A cumulative risk score is calculated by simply adding each Inntinn device score up. Just that simple.

### One final note on scores
**Device** and **Org** scores will change over time as threats evolve and new information becomes available. While the underlying data sets outlined in the "Per Device" section above will not necessarily change, scores will fluctuate between database updates nonetheless.

Database updates are performed at an interval of your choosing, however we recommend at least once weekly.

## Installation and Usage _(Technical)_

1) OS X, Linux & Windows:

```sh
pip install inntinn
```
2) Ensure that a working MongoDB database is accessible and utilize the [Example configuration file](https://github.com/BlackburnHax/inntinn/blob/main/example_config.json) to enable read/write on the given MongoDB database.

Example Config:
```json
{"inntinn":{"instance":"thedb",
       "user": "audrey",
       "pass": "asdfghjjkl12345",
       "uri": "mongodb://4.2.2.2:27017/"}}
```
3) Import Inntinn within your Python code, instance the database, provide it the config file and perform an update to populate the database:
```python
import inntinn
db = inntinn.Database("/path/to/your/config.json")

db.update()
```
4) **a)** Lookup the SEC CIK for your chosen company:
```python
import inntinn
db = inntinn.Database("/path/to/your/config.json")

companies = db.cik_lookup("apple")
for key, value in companies.items():
    print(f"CIK: {key} = {value}")
```

**b)** Or if you are feeling lucky, just use the company name:
```python
import inntinn
db = inntinn.Database("/path/to/your/config.json")

device_score = db.score_device_list_fuzzy(["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0840", "CVE-2021-22721", "CVE-2021-3619"], "Apple Inc")
```

5) If you didn't opt for option "b" above, you may now perform scoring:
```python
import inntinn
db = inntinn.Database("/path/to/your/config.json")

device_score = db.score_device_list(["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0840", "CVE-2021-22721", "CVE-2021-3619"], 320193)
```

6) After performing scoring on a **Per Device** level for each device in the org, you may calculate the **Per Org** score:
```python
import inntinn
db = inntinn.Database("/path/to/your/config.json")

device_a_score = db.score_device_list(["CVE-2019-0708", "CVE-1999-0019", "CVE-2018-0840", "CVE-2021-22721", "CVE-2021-3619"], 320193)
# any number of device calculations here
device_z_score = db.score_device_list(["CVE-2021-2336", "CVE-2021-2390", "CVE-2018-0840", "CVE-2019-0708"], 320193)
org_score = db.score_org([device_a_score, device_z_score])
```
## API
Optionally, Inntinn has an accompanying [Sanic](https://sanicframework.org/) based API which does not require a proxy like most Python frameworks.
To view the documentation for the API visit [**bhax.net/api**](https://bhax.net/api)

[![API Documentation: Swagger](https://img.shields.io/badge/API%20Docs-Swagger-blue)](https://bhax.net/api)


The API is functional and fast, but we **do not** recommend running it on Windows as multi-threading is not available at this time. Running on Windows will result in dramatically slower response processing.

### Getting started

The [API itself is located under inntinn/api.py](https://github.com/BlackburnHax/inntinn/blob/main/inntinn/api.py) and must be launched with appropriate permissions to open sockets on Port 80 & Port 443.

Use the [example_config.json](https://github.com/BlackburnHax/inntinn/blob/main/example_config.json) and be pay close attention to the "inntinn_api" section.
Generate your certs and set the config to point to the files.

**Important Note:** Currently, the config.json must be called "config.json" and placed in the same directory as the api.py application.
_(This behavior is likely to change in a future update allowing one to pass the config as a command line argument at launch)_

## Meta

Brandon Blackburn – [PGP Encrypted Chat @ Keybase](https://keybase.io/blackburnhax/chat)

Distributed under the Apache 2.0 license. See ``LICENSE`` for more information.

_TL;DR:_
For a human-readable & fast explanation of the Apache 2.0 license visit:  http://www.tldrlegal.com/l/apache2


[https://github.com/BlackburnHax/inntinn](https://github.com/BlackburnHax/inntinn)