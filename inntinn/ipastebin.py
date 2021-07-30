# BEFORE USING: Visit the following page and follow the instructions: https://pastebin.com/doc_scraping_api
import datetime
import json
import pathlib
import time

from blackburn import load_json_file, TZ, time_stamp_convert
import mongoblack
from typing import Union
import warnings
import re
import requests
from threading import Thread
import pymongo
import gzip
import random

"""pastebin: Pastebin spider for Inntinn.io"""

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


class IPastebin:
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

        if isinstance(config_json, (str, pathlib.Path)):
            config_path = pathlib.Path(config_json)
        self.config = load_json_file(config_path)
        self.db = self._connect_db()
        self.cve_spider_pattern = re.compile(
            "(CVE[ _-][0-9]{4}[ _-][0-9]{3,7})", re.IGNORECASE
        )
        self.cve_parts_pattern = re.compile(
            "CVE[ _-]([0-9]{4})[ _-]([0-9]{3,7})", re.IGNORECASE
        )
        self.time_gate_seconds = 10

        warnings.filterwarnings("ignore")

    def _connect_db(self):
        return mongoblack.Connection(
            self.config["inntinn"]["instance"],
            self.config["inntinn"]["user"],
            self.config["inntinn"]["pass"],
            self.config["inntinn"]["uri"],
            **self.kwargs,
        )

    @staticmethod
    def _zip(string_to_compress: str) -> bytes:
        return gzip.compress(string_to_compress.encode())

    @staticmethod
    def _unzip(bytes_to_unzip: bytes) -> str:
        return gzip.decompress(bytes_to_unzip).decode()

    def _conform_cve(self, string_to_conform: str):
        parts = self.cve_parts_pattern.match(string_to_conform).groups()
        return f"CVE-{parts[0]}-{parts[1]}"

    def _spider_text_cve(self, text_to_read: str) -> list:
        if text_to_read is None:
            return []
        found_cves = set([])
        results = self.cve_spider_pattern.findall(text_to_read)
        for match in results:
            cve = self._conform_cve(match)
            found_cves.add(cve)
        return list(found_cves)

    def _spider_ingest(self, text_to_read, source_db, source_reference) -> list:
        results = self._spider_text_cve(text_to_read)
        if len(results) < 1:
            return []
        discovered = []
        for referenced_cve in results:
            referenced_cve = referenced_cve.strip().upper()
            cve_doc = self.db.get(source_db, referenced_cve)
            if cve_doc is None:
                cve_doc = {"sources": [source_reference]}
                discovered.append(referenced_cve)
            else:
                original_size = len(cve_doc["sources"])
                sources = set(cve_doc["sources"])
                sources.add(source_reference.strip())
                sources = list(sources)
                cve_doc["sources"] = sources
                new_size = len(cve_doc["sources"])
                if new_size > original_size:
                    discovered.append(referenced_cve)
            self.db.write(source_db, cve_doc, referenced_cve)
        return discovered

    def _precache_pastebin(self):
        print("Starting precache...")
        cache = "pastebin_precache"
        paste_bin_url = "https://scrape.pastebin.com/api_scraping.php?limit=100"
        response = requests.get(paste_bin_url)
        raw_results = response.json()
        for result in raw_results:
            source = result["full_url"]
            raw_url = (
                f"https://scrape.pastebin.com/api_scrape_item.php?i={result['key']}"
            )
            time_stamp = TZ.is_utc(datetime.datetime.fromtimestamp(int(result["date"])))
            time_stamp = time_stamp_convert(time_stamp)
            document = {
                "source": source,
                "raw_url": raw_url,
                "pastebin_key": result["key"],
                "date": time_stamp,
            }
            self.db.write(cache, document, result["key"])
        print("Precache Complete.")

    def _cache_pastebin(self, reversed=False):
        cache = "pastebin_precache"
        if reversed:
            print("Starting Caching thread B...")
            time.sleep(
                5 * random.random()
            )  # staggering threads to reduce resource contention
        else:
            print("Starting Caching thread A...")
            time.sleep(
                5 * random.random()
            )  # staggering threads to reduce resource contention
        while True:
            if reversed:
                cached_pastes = self.db.get_all(cache).sort("_id", pymongo.DESCENDING)
            else:
                cached_pastes = self.db.get_all(cache)
                number_of_cached_pastes = self.db.count(cache)
                if number_of_cached_pastes < 200 and reversed:
                    time.sleep(5 * random.random())
                    continue
            for entry in cached_pastes:
                pre_existing_doc = self.db.get("pastebin_cache", entry["pastebin_key"])
                if pre_existing_doc is not None:
                    continue  # To avoid loading PasteBin's servers and our own, we track and skip any pastes we already have
                attempts = 0
                if reversed:
                    print(f"thread B processing: {entry['source']}")
                else:
                    print(f"thread A processing: {entry['source']}")
                while True:
                    try:
                        result = requests.get(entry["raw_url"])
                        break
                    except requests.exceptions.ConnectionError:
                        time.sleep(0.5)
                        attempts += 1
                    if attempts > 5:
                        time.sleep(5)

                if result.status_code == 200:
                    compressed = self._zip(result.text)
                    document = {
                        "gzip": compressed,
                        "source": entry["source"],
                        "pastebin_key": entry["pastebin_key"],
                        "date": entry["date"],
                    }
                    success_status = self.db.write(
                        "pastebin_cache", document, entry["pastebin_key"]
                    )
                    if success_status.acknowledged:
                        self.db.delete(cache, entry["_id"])
            time.sleep(2)

    def _process_pastebin_cache(self):
        cache = "pastebin_cache"
        while True:
            queue = self.db.get_all(cache)
            pastebin_entries = 0
            for entry in queue:
                results = []

                plaintext = self._unzip(entry["gzip"])

                results.extend(
                    self._spider_ingest(plaintext, "pastebin", entry["source"])
                )

                if len(results) > 0:
                    print(f"Found {results}")
                pastebin_entries += 1

            print(f"Scanned {pastebin_entries} cached pastes.")
            time.sleep(10)

    def start(self):
        Thread(target=self._process_pastebin_cache).start()
        Thread(target=self._cache_pastebin).start()
        Thread(target=self._cache_pastebin, args=(True,)).start()
        while True:
            try:
                self._precache_pastebin()
            except json.JSONDecodeError:
                pass
            start_time = datetime.datetime.now()

            while True:
                differential = (datetime.datetime.now() - start_time).seconds
                if differential > self.time_gate_seconds:
                    break
                else:
                    time.sleep(0.5)
