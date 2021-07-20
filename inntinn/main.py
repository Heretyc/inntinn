import datetime
import zipfile
import requests
from io import BytesIO
import json
import pathlib
import math


"""main.py: OSINT composite vulnerability database"""

__author__ = "Brandon Blackburn"
__maintainer__ = "Brandon Blackburn"
__email__ = "contact@bhax.net"
__website__ = "https://keybase.io/blackburnhax"
__copyright__ = "Copyright 2021 Brandon Blackburn"
__license__ = "Apache 2.0"

#  Copyright (c) 2021. Brandon Blackburn - https://keybase.io/blackburnhax, Apache License, Version 2.0.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
#  either express or implied. See the License for the specific
#  language governing permissions and limitations under the License.
#  TL;DR:
#  For a human-readable & fast explanation of the Apache 2.0 license visit:  http://www.tldrlegal.com/l/apache2


class Inntinn:
    def __init__(self):
        self.master_dict = {}
        self.company_dict = {}
        self.temp_dir = pathlib.Path.cwd() / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        pass

    def _parse_download(self, nvd_zipped_json):
        result = requests.get(nvd_zipped_json, stream=True)
        zip_object = zipfile.ZipFile(BytesIO(result.content))
        json_object = zip_object.read(zip_object.filelist[0].filename)
        raw_list = json.loads(json_object)["CVE_Items"]
        for list_item in raw_list:
            cve_id = list_item["cve"]["CVE_data_meta"]["ID"]
            descriptions = list_item["cve"]["description"]["description_data"]
            selected_description = ""
            for description_item in descriptions:
                if description_item["lang"] == "en":
                    selected_description = description_item["value"]
                    break

            references = set([])
            for ref_item in list_item["cve"]["references"]["reference_data"]:
                references.add(ref_item["url"])
            references = list(references)

            try:
                v3_score = list_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            except KeyError:
                v3_score = -1

            try:
                v2_score = list_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            except KeyError:
                v2_score = -1

            try:
                obtainAllPrivilege = list_item["impact"]["baseMetricV2"][
                    "obtainAllPrivilege"
                ]
            except KeyError:
                obtainAllPrivilege = False

            try:
                obtainUserPrivilege = list_item["impact"]["baseMetricV2"][
                    "obtainUserPrivilege"
                ]
            except KeyError:
                obtainUserPrivilege = False

            try:
                obtainOtherPrivilege = list_item["impact"]["baseMetricV2"][
                    "obtainOtherPrivilege"
                ]
            except KeyError:
                obtainOtherPrivilege = False

            try:
                userInteractionRequired = list_item["impact"]["baseMetricV2"][
                    "userInteractionRequired"
                ]
            except KeyError:
                userInteractionRequired = False

            self.master_dict[cve_id] = {
                "description": selected_description,
                "references": references,
                "obtainAllPrivilege": obtainAllPrivilege,
                "obtainUserPrivilege": obtainUserPrivilege,
                "obtainOtherPrivilege": obtainOtherPrivilege,
                "userInteractionRequired": userInteractionRequired,
                "v3_score": v3_score,
                "v2_score": v2_score,
            }

    @staticmethod
    def _load_json_file(json_file):
        """
        Loads a given JSON file into memory and returns a dictionary containing the result
        :param json_file: JSON file to load
        :type json_file: str
        :rtype: dict
        """
        file_path = pathlib.Path(json_file)
        try:
            with open(file_path, "r") as json_data:
                return json.load(json_data)
        except FileNotFoundError:
            print(f"Error: {file_path} not found.")
            raise FileNotFoundError

    def _company_risk_rank(self):
        rankings_dict = {}
        for key, value in self.company_dict.items():
            rankings_dict[key] = value["assets"]

        sorted_rankings = sorted(
            rankings_dict.items(), key=lambda x: x[1], reverse=False
        )
        number_of_companies = len(sorted_rankings)
        ranking = 0
        for item in sorted_rankings:
            ranking += 1
            self.company_dict[item[0]]["risk_rank"] = ranking
            self.company_dict[item[0]]["risk_base_score"] = (
                math.sqrt(ranking / number_of_companies) * 10
            )

    def company_read(self):
        for path in sorted(self.temp_dir.rglob("*")):
            company_dict = self._load_json_file(path)
            try:
                company_name = company_dict["entityName"]
            except KeyError:
                continue  # Malformed JSON, so skip
            try:
                sec_url = f"https://www.sec.gov/edgar/browse/?CIK={company_dict['cik']}"
            except KeyError:
                continue  # Malformed JSON, so skip

            try:
                assets = company_dict["facts"]["us-gaap"]["Assets"]["units"]["USD"][0][
                    "val"
                ]
            except KeyError:
                continue  # Company lacks asset info, so skipping
            self.company_dict[company_dict["cik"]] = {
                "name": company_name,
                "sec_url": sec_url,
                "assets": assets,
            }

    def company_download(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36"
        }

        result = requests.get(
            "http://www.sec.gov/Archives/edgar/daily-index/xbrl/companyfacts.zip",
            headers=headers,
            stream=True,
        )
        master_zip = zipfile.ZipFile(BytesIO(result.content))
        master_zip.extractall(path=self.temp_dir)

    def download(self):
        current_year = datetime.date.today().year
        print("Downloading entire NVD database...")
        for year in range(2002, current_year + 1):
            print(f"Reading data for year {year}")
            self._parse_download(
                f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
            )
        print("Reading recent data...")
        self._parse_download(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
        )
        print("Reading updated data...")
        self._parse_download(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
        )

    def score(self, cve, cik):
        pass
