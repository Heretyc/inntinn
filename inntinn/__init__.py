import csv
import datetime
import json
import math
import pathlib
import re
import warnings
import zipfile
from io import BytesIO
from typing import Union

import mongoblack
import numpy
import requests
from blackburn import LockFile, load_json_file
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
    def __init__(self, config_json: Union[str, pathlib.Path], **kwargs):
        """
        Initializes the database connection using the supplied configuration file.
        :param config_json: Pathlib path, or string containing the path to the configuration JSON file
        :keyword compression: MongoDB Zlib compression level (default: 1)
        :keyword tls: MongoDB SSL/TLS state (default: True)
        :keyword retries: MongoDB Number of attempted retries for operations
        :keyword timeout: MongoDB Cool-down period in seconds between successive retries (default: 0.5)
        """
        self.kwargs = kwargs
        self.master_dict = {}
        self.company_dict = {}
        self.temp_dir = pathlib.Path.cwd() / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.lock = LockFile(self.temp_dir / "database.lock")

        if isinstance(config_json, (str, pathlib.Path)):
            config_path = pathlib.Path(config_json)
        self.config = load_json_file(config_path)
        self.db = self._connect_db()
        self.english_pattern = re.compile("^[a-zA-Z0-9._# -]*$")
        self.cve_pattern = re.compile("^CVE-\d{4}-(0\d{3}|[1-9]\d{3,})$", re.IGNORECASE)
        warnings.filterwarnings("ignore")

    def _parse_download(self, nvd_zipped_json: str) -> None:
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
                obtain_all_privilege = list_item["impact"]["baseMetricV2"][
                    "obtainAllPrivilege"
                ]
            except KeyError:
                obtain_all_privilege = False

            try:
                obtain_user_privilege = list_item["impact"]["baseMetricV2"][
                    "obtainUserPrivilege"
                ]
            except KeyError:
                obtain_user_privilege = False

            try:
                obtain_other_privilege = list_item["impact"]["baseMetricV2"][
                    "obtainOtherPrivilege"
                ]
            except KeyError:
                obtain_other_privilege = False

            try:
                user_interaction_required = list_item["impact"]["baseMetricV2"][
                    "userInteractionRequired"
                ]
            except KeyError:
                user_interaction_required = False

            self.master_dict[cve_id] = {
                "description": selected_description,
                "references": references,
                "obtainAllPrivilege": obtain_all_privilege,
                "obtainUserPrivilege": obtain_user_privilege,
                "obtainOtherPrivilege": obtain_other_privilege,
                "userInteractionRequired": user_interaction_required,
                "v3_score": v3_score,
                "v2_score": v2_score,
            }

    def _download_exploitdb(self):
        print("Downloading exploit intelligence database...")
        with requests.Session() as context:
            download = context.get(
                "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
            )
            decoded_content = download.content.decode("utf-8")
            reader = csv.DictReader(decoded_content.splitlines(), delimiter=",")
            for row in reader:
                doc = {"description": row["description"], "date": row["date"]}
                self.db.write("exploits", doc, row["id"])

    def _sanitize(self, text: str) -> str:
        found = self.english_pattern.search(text)
        if found is None:
            raise ValueError("Received a string with special characters beyond ._# -")
        return str(found.group())

    def _company_risk_rank(self):
        assert len(self.company_dict) > 1  # Need to load company JSONs first
        print("Performing risk ranking calculations...")
        rankings_dict = {}
        for key, value in self.company_dict.items():
            rankings_dict[key] = value["assets"]

        sorted_rankings = sorted(
            rankings_dict.items(), key=lambda x: x[1], reverse=False
        )
        number_of_companies = len(sorted_rankings)
        ranking = 0
        score = 0
        for item in reversed(sorted_rankings):
            ranking += 1
            self.company_dict[item[0]]["risk_rank"] = ranking
            score = (-(math.sqrt(ranking / number_of_companies) * 10) + 11) * 0.9
            self.company_dict[item[0]]["risk_base_score"] = score

        self.db.write(
            "configuration",
            {"base_score": str(score)},
            "core_config",
        )

    def _connect_db(self):
        return mongoblack.Connection(
            self.config["inntinn"]["instance"],
            self.config["inntinn"]["user"],
            self.config["inntinn"]["pass"],
            self.config["inntinn"]["uri"],
            **self.kwargs,
        )

    @staticmethod
    def _confidence(target_list: list) -> int:
        data = numpy.array(target_list)
        try:
            avg = data.mean()
        except RuntimeWarning:
            pass
        variability = data.std()
        accuracy = 100 - ((variability / avg) * 100)
        return round(accuracy)

    def _company_read(self):
        print("Parsing SEC database data...")
        for path in sorted(self.temp_dir.rglob("*.json")):
            company_dict = load_json_file(path)
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
        print("Pushing SEC data to database...")
        for key, value in self.company_dict.items():
            self.db.write("companies", value, key)
        print("Cleaning up temporary files...")
        for path in sorted(self.temp_dir.rglob("*.json")):
            pathlib.Path(path).unlink()

    def _download_sec(self):
        print("Downloading SEC database...")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36"
        }

        result = requests.get(
            "https://www.sec.gov/Archives/edgar/daily-index/xbrl/companyfacts.zip",
            headers=headers,
            stream=True,
        )
        master_zip = zipfile.ZipFile(BytesIO(result.content))
        print("Extracting downloaded data...")
        master_zip.extractall(path=self.temp_dir)

    def _download_cve(self) -> None:
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
        print("Pushing latest findings to database...")
        for key, value in self.master_dict.items():
            self.db.write("cves", value, key)

    def _read_config_for(self, config_item: str) -> str:
        return self.db.get("configuration", "core_config")[config_item]

    def update(self):
        """
        Updates all internal databases using freshly downloaded data
        """
        with self.lock:
            self._download_exploitdb()
            self._download_sec()
            self._company_read()
            self._download_cve()

    def _validate_cve(self, cve: str) -> str:
        if not isinstance(cve, str):
            raise ValueError("CVEs must be strings")
        cve = self._sanitize(cve)

        found_cve = self.cve_pattern.search(cve)
        if found_cve is None:
            raise ValueError(f"Improperly formatted CVE - {cve}")
        return str(found_cve.group()).upper()

    def cve_lookup(self, cve: str) -> dict:
        """
        Retrieve available information on a given NVD CVE ID
        :param cve: NVD CVE ID (ex: CVE-yyyy-#####)
        :return: Dictionary of all available information on the given CVE
        """
        cve = self._validate_cve(cve)
        return self.db.get("cves", cve)

    def cik_lookup(self, company_name: str) -> dict:
        """
        Looks up all matching companies given the supplied company name
        Returns a dict in the format {cik:company}
        :param company_name: (case-insensitive) all or partial name of company to search for
        :return: dict: a dictionary where each key:value is cik:company
        """
        company_name = self._sanitize(company_name)
        final_result = {}
        query = {}
        query["name"] = Regex(f".*{company_name}.*", "i")

        for item in self.db.get_all("companies", query):
            final_result[item["_id"]] = item["name"]
        return final_result

    def _get_score(self, cve: str, company_score_list: list) -> tuple:

        cve_doc = self.db.get("cves", self._validate_cve(cve))
        if cve_doc is None:
            raise LookupError("CVE does not exist.")
        if cve_doc["v3_score"] > -1:
            cvss = cve_doc["v3_score"]
        else:
            cvss = cve_doc["v2_score"]

        notoriety = len(cve_doc["references"])

        query = {}
        query["description"] = Regex(f".*{cve}.*", "i")
        exploit_count = self.db.count("exploits", query)

        average = numpy.mean(numpy.array(company_score_list))

        try:
            company_score = average * 1  # Testing if we averaged out a number or 'nan'
            confidence = self._confidence(company_score_list)
        except ValueError:
            company_score = float(self._read_config_for("base_score"))
            confidence = -1
        final_score = math.ceil(
            (company_score * cvss)
            + (cvss * math.sqrt(exploit_count * 4))
            + (math.sqrt(notoriety) * 4)
        )

        final_score = int(final_score)

        if final_score < 0:
            final_score = 0
        elif final_score > 100:
            final_score = 100

        return final_score, confidence

    def score_device_fuzzy(self, cve: str, company_name: str) -> tuple:
        """
        Computes the final composite Inntinn score given a portion of a company name and CVE
        The final Tuple returned contains the score and the confidence in said score (out of 100)
        :param cve: NVD CVE ID which a given device is vulnerable
        :param company_name: (case-insensitive) all or partial company name which owns the given device
        :return: (int,int): Tuple of (final composite score, % confidence in score)
        """
        company_name = self._sanitize(company_name)

        base_scores = []
        query = {}
        query["name"] = Regex(f".*{company_name}.*", "i")

        for item in self.db.get_all("companies", query):
            base_scores.append(item["risk_base_score"])

        final_score, confidence = self._get_score(cve, base_scores)

        return final_score, confidence

    def score_device(self, cve: str, cik: [int, str]) -> int:
        """
        Computes the final composite Inntinn score given a specific company CIK and CVE
        :param cve: NVD CVE ID which a given device is vulnerable
        :param cik: SEC CIK identifier of a company which owns the given device
        :return: int: final composite score
        """
        if not isinstance(cve, str):
            raise ValueError("Only strings are accepted for CVE")
        if not isinstance(cik, (str, int)):
            raise ValueError("CIK may only be an integer or string")
        company_doc = self.db.get("companies", int(cik))

        if company_doc is None:
            raise LookupError(
                f"No company with CIK {int(cik)} exists in the SEC database"
            )

        final_score, confidence = self._get_score(cve, [company_doc["risk_base_score"]])

        return final_score

    @staticmethod
    def _get_score_list(score_list: list) -> int:
        data = numpy.array(score_list)
        mean = data.mean()
        variance = data.std()

        # removing scores that are less than 1 standard deviation from average. So low outliers.
        cleaned_data = []
        for value in data:
            if value > mean - variance:
                cleaned_data.append(value)

        # Now recalculate with the adjusted array
        final_score = int(math.ceil(numpy.array(cleaned_data).mean()))

        return final_score

    def score_device_list(self, list_of_cves: list, cik: int) -> int:
        """
        Calculate a final score for a given device which is vulnerable to the list_of_cves and is found in the
        company identified by CIK
        :param list_of_cves: The list of CVEs which the device is vulnerable to
        :param cik: The company CIK which owns the device
        :return: int: final composite score
        """
        scores = []
        for cve in list_of_cves:
            scores.append(self.score_device(cve, cik))

        final_score = self._get_score_list(scores)

        return final_score

    def score_device_list_fuzzy(self, list_of_cves: list, company_name: str) -> tuple:
        """
        Calculate a final score for a given device which is vulnerable to the list_of_cves and is found in the
        company identified by company_name (case insensitive)
        :param list_of_cves: The list of CVEs which the device is vulnerable to
        :param company_name: The company which owns the device (case-insensitive, partial match)
        :return: (int,int): Tuple of (final composite score, % confidence in score)
        """
        scores = []
        for cve in list_of_cves:
            score, confidence = self.score_device_fuzzy(cve, company_name)
            # we don't need to average the confidence scores as they all will be equal
            scores.append(score)

        final_score = self._get_score_list(scores)

        return final_score, confidence

    @staticmethod
    def score_org(list_of_inntinn_scores: list) -> int:
        """
        Creates a single company-wide score that can measure overall risk in relation to other companies, or over time.
        Uses a high-efficiency summation of the provided device Inntinn scores in order to arrive at score.
        :param list_of_inntinn_scores: A list containing the output of score_list() from all known devices
        :return: an integer measuring the total risk of a company which can be compared to other companies
        """
        return int(numpy.sum(list_of_inntinn_scores))
