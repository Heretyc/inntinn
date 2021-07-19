import datetime
import zipfile
import requests
from io import BytesIO
import json

"""inntinn.py: OSINT composite vulnerability database"""

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
        pass

    def download(self):
        current_year = datetime.date.today().year
        for year in range(2002, current_year):
            result = requests.get(f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip", stream=True)
            zip_object = zipfile.ZipFile(BytesIO(result.content))
            json_object = zip_object.read(zip_object.filelist[0].filename)
            raw_list = json.loads(json_object)['CVE_Items']
            for list_item in raw_list:
                cve_id = list_item['cve']['CVE_data_meta']['ID']
                description = list_item['cve']['description']['description_data']
                self.master_dict[cve_id] = description
        self.master_dict
