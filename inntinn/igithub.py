import pathlib
from blackburn import load_json_file
import pymongo
import mongoblack
from typing import Union
import warnings
import re
from github import Github
import github.GithubException
import requests
import datetime
from blackburn import time_stamp_convert, TZ
import time
from threading import Thread

"""pastebin: Pastebin spider for Inntinn"""

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


class IGitHub:
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

        warnings.filterwarnings("ignore")

    def _connect_db(self):
        return mongoblack.Connection(
            self.config["inntinn"]["instance"],
            self.config["inntinn"]["user"],
            self.config["inntinn"]["pass"],
            self.config["inntinn"]["uri"],
            **self.kwargs,
        )

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

    def _process_github_cache(self):
        cache = "github_cache"
        while True:
            queue = self.db.get_all(cache)
            github_entries = 0
            for entry in queue:
                results = []
                try:
                    readme = entry["readme"]
                    results.extend(
                        self._spider_ingest(readme, "github", entry["clone_url"])
                    )
                except KeyError:
                    pass
                try:
                    description = entry["description"]
                    results.extend(
                        self._spider_ingest(description, "github", entry["clone_url"])
                    )
                except KeyError:
                    pass

                if len(results) > 0:
                    print(f"Found {results}")
                github_entries += 1

            print(f"Scanned {github_entries} cached repos.")
            time.sleep(300)

    def _github_check_rate_limit(self):
        git = Github(self.config["inntinn"]["github_token"])
        try:
            rate_limit = git.get_rate_limit()
        except requests.exceptions.ConnectTimeout:
            return
        remaining = rate_limit.raw_data["core"]["remaining"]

        reset_time = TZ.is_utc(
            datetime.datetime.fromtimestamp(rate_limit.raw_data["core"]["reset"])
        )
        reset_time_local = TZ.to_local(reset_time)
        print(f"GitHub has {remaining} remaining")
        if remaining < 1:
            print("GitHub API rate limit reached, standing by for reset")
            time.sleep(60)

    def _cache_github(self):
        cache = "github_cache"
        self._github_check_rate_limit()
        git = Github(self.config["inntinn"]["github_token"])
        import pymongo

        last_id_intermediate = (
            self.db.get_all(cache).sort("_id", pymongo.DESCENDING).limit(1)
        )
        for last_id_item in last_id_intermediate:
            last_id = last_id_item["_id"]
        all_repos = git.get_repos(since=last_id)

        count = 0
        consecutive_errors = 0
        readme_extensions = [
            ".md",
            ".txt",
            ".markdown",
            "",
            ".rdoc",
            ".textile",
            ".rst",
            ".creole",
            ".mediawiki",
            ".wiki",
            ".org",
            ".asciidoc",
            ".adoc",
            ".asc",
            ".pod",
            ".mdown",
            ".mkdn",
        ]
        for repo in all_repos:
            count += 1
            if count % 1000 == 0:
                self._github_check_rate_limit()
            # self._spider_ingest(repo.description, "github", repo.html_url)
            try:
                branch_url = f"https://raw.githubusercontent.com/{repo.full_name}/{repo.default_branch}/README"

                for file_extension in readme_extensions:
                    readme_url = f"{branch_url}{file_extension}"
                    response = requests.get(readme_url)
                    if response.status_code == 404:
                        continue
                    else:
                        break

                if response.status_code == 404:
                    readme = ""
                else:
                    readme = response.text

                document = {
                    "html_url": repo.html_url,
                    "readme": readme,
                    "clone_url": repo.clone_url,
                    "created_at": time_stamp_convert(
                        TZ.to_local(TZ.is_utc(repo.created_at))
                    ),
                    "description": repo.description,
                    "forks": repo.forks_count,
                    "full_name": repo.full_name,
                    "homepage": repo.homepage,
                    "language": repo.language,
                    "pushed_at": time_stamp_convert(
                        TZ.to_local(TZ.is_utc(repo.pushed_at))
                    ),
                }
                consecutive_errors = 0
            except (
                AttributeError,
                github.GithubException,
                requests.exceptions.ConnectionError,
            ):
                consecutive_errors += 1
                if consecutive_errors > 10:
                    print(f"Consecutive errors: {consecutive_errors}")
                continue
            self.db.write(cache, document, repo.id)

            print(f"Processed: {count} repos")
        return count

    def start(self):
        # self._process_github_cache()
        Thread(target=self._process_github_cache).start()
        self._cache_github()
