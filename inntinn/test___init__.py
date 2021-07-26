from unittest import TestCase
import inntinn
import pathlib


class Test_Entries:
    def __init__(self, it_db: inntinn.Database):
        assert isinstance(it_db, inntinn.Database)

        self.test_company_payload = {
            "assets": 39572000000,
            "name": "test_company",
            "risk_base_score": 8.817629719675926,
            "risk_rank": 192,
            "sec_url": "http://inntinn.io",
        }

        self.test_cve_payload = {
            "description": "Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are affected are 5.7.34 and prior and 8.0.25 and prior. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).",
            "obtainAllPrivilege": False,
            "obtainOtherPrivilege": False,
            "obtainUserPrivilege": False,
            "references": ["http://inntinn.io"],
            "userInteractionRequired": False,
            "v2_score": 2.2,
            "v3_score": 5.9,
        }

        self.db = it_db

    def __enter__(self):
        self.db.db.write("companies", self.test_company_payload, 999999999)
        self.db.db.write("cves", self.test_cve_payload, "CVE-2500-1111")

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.db.delete("companies", 999999999)
        self.db.db.delete("cves", "CVE-2500-1111")
        pass


class Test_Database(TestCase):
    def setUp(self):
        self.db = inntinn.Database(pathlib.Path.cwd().parent / "config.json", tls=False)
        self.testing_entries = Test_Entries(self.db)

    def test_cve_lookup(self):
        with self.testing_entries:
            good = self.db.cve_lookup("cve-2500-1111")
            assert isinstance(good, dict)
            assert good["_id"] == "CVE-2500-1111"

            try:
                bad = self.db.cve_lookup("gpa-2500-1111")
                assert not isinstance(bad, dict)
            except ValueError:
                assert True

            try:
                bad = self.db.cve_lookup("CVE-1111-0708")
                assert not isinstance(bad, dict)
            except ValueError:
                assert True

            try:
                bad = self.db.cve_lookup("CVE 2500 1111")
                assert not isinstance(bad, dict)
            except ValueError:
                assert True

        try:
            bad = self.db.cve_lookup("CVE 2019-0708")
            assert not isinstance(bad, dict)
        except ValueError:
            assert True

    def test_cik_lookup(self):
        with self.testing_entries:
            result = self.db.cik_lookup("test_company")
        assert result[999999999] == "test_company"

    def test_score_device_fuzzy(self):
        with self.testing_entries:
            result = self.db.score_device_fuzzy("CVE-2500-1111", "test_company")
            assert result == (57, 100)

    def test_score_device(self):
        with self.testing_entries:
            result = self.db.score_device("CVE-2500-1111", 999999999)
            assert result == 57

    def test_score_device_list(self):
        with self.testing_entries:
            result = self.db.score_device_list(
                ["CVE-2500-1111", "CVE-2500-1111", "CVE-2500-1111"], 999999999
            )

        assert result == 57

    def test_score_device_list_fuzzy(self):
        with self.testing_entries:
            result = self.db.score_device_list_fuzzy(
                ["CVE-2500-1111", "CVE-2500-1111", "CVE-2500-1111"], "test_company"
            )

        assert result == (57, 100)

    def test_score_org(self):
        result = self.db.score_org([22, 15, 27, 33, 99, 100, 10, 16, 45, 34, 16])
        assert result == 417
