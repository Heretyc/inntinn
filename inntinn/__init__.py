import datetime
import zipfile
import requests
from io import BytesIO
import json
import pathlib
import math
import mongoblack
import numpy
from bson.regex import Regex


"""inntinn: OSINT composite vulnerability database"""

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


class Database:
    def __init__(self, config_json, **kwargs):
        self.kwargs = kwargs
        self.master_dict = {}
        self.company_dict = {}
        self.temp_dir = pathlib.Path.cwd() / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(config_json, (str, pathlib.Path)):
            config_path = pathlib.Path(config_json)
        self.config = self._load_json_file(config_path)
        self.db = self._connect_db()

    def _parse_download(self, nvd_zipped_json):
        result = requests.get(nvd_zipped_json, stream=True)
        zip_object = zipfile.ZipFile(BytesIO(result.content))
        json_object = zip_object.read(zip_object.filelist[0].filename)
        raw_list = json.loads(json_object)["CVE_Items"]
        print("Download complete, parsing database...")
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
        print("Performing risk ranking calculations...")
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
            item

    def _connect_db(self):
        return mongoblack.Connection(
            self.config["db"]["instance"],
            self.config["db"]["user"],
            self.config["db"]["pass"],
            self.config["db"]["uri"],
            **self.kwargs,
        )

    def _company_read(self):
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
        self._company_risk_rank()
        for key, value in self.company_dict.items():
            self.db.write("companies", value, key)
        self.company_dict

    def _company_download(self):
        print("Downloading SEC database...")
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

    def _download(self):
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
        for key, value in self.master_dict.items():
            self.db.write("cves", value, key)

    def update(self):
        """
        Updates all internal databases using freshly downloaded data
        """
        self._company_download()
        self._company_read()
        self._download()

    def cik_lookup(self, company_name):
        """
        Looks up all matching companies given the supplied company name
        Returns a dict in the format {cik:company}
        :param company_name: (case-insensitive) all or partial name of company to search for
        :return: dict: a dictionary where each key:value is cik:company
        """
        final_result = {}
        query = {}
        query["name"] = Regex(f".*{company_name}.*", "i")

        for item in self.db.get_all("companies", query):
            final_result[item["_id"]] = {item["name"]}
        return final_result

    def score_fuzzy(self, cve, company_name):
        """
        Computes the final composite Inntinn score given a portion of a company name and CVE
        The final Tuple returned contains the score and the number of companies which went into said score
        :param cve: NVD CVE ID which a given device is vulnerable
        :param company_name: (case-insensitive) all or partial company name which owns the given device
        :return: (int,int): Tuple of (final composite score, number of companies matched)
        """
        cve_doc = self.db.get("cves", cve)
        if cve_doc["v3_score"] > -1:
            score = cve_doc["v3_score"]
        else:
            score = cve_doc["v2_score"]

        base_scores = []
        query = {}
        query["name"] = Regex(f".*{company_name}.*", "i")

        for item in self.db.get_all("companies", query):
            base_scores.append(item["risk_base_score"])
        average = numpy.mean(
            numpy.array(base_scores)
        )  # Fastest way to average a list: https://stackoverflow.com/questions/58016779/fastest-way-to-compute-average-of-a-list

        return (round(average * score), len(base_scores))

    def score(self, cve, cik):
        """
        Computes the final composite Inntinn score given a specific company CIK and CVE
        :param cve: NVD CVE ID which a given device is vulnerable
        :param cik: SEC CIK identifier of a company which owns the given device
        :return: int: final composite score
        """
        company_doc = self.db.get("companies", int(cik))
        cve_doc = self.db.get("cves", cve)
        if cve_doc["v3_score"] > -1:
            score = cve_doc["v3_score"]
        else:
            score = cve_doc["v2_score"]

        return round(company_doc["risk_base_score"] * score)
