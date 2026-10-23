import importlib.util
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = importlib.util.spec_from_file_location(
    "harvest_bb_skills",
    os.path.join(ROOT, "scripts", "harvest-bb-skills.py"),
)
harvest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harvest)


SKILL = "# SQLi\n\nLook for a boolean difference. Do not claim a hit without two responses.\n"


def plant(files):
    def clone(repo, dest):
        spec = files.get(repo)
        if spec is None:
            return False
        os.makedirs(dest, exist_ok=True)
        for rel, content in spec.items():
            path = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
        return True

    return clone


class HarvestTests(unittest.TestCase):
    def test_content_hash_dedupes_and_records_the_kept_file(self):
        with tempfile.TemporaryDirectory() as staging:
            result = harvest.harvest_sources(
                ["alpha/one", "beta/two"],
                staging,
                plant({
                    "alpha/one": {"LICENSE": "MIT License\n\nPermission is hereby granted\n", "skills/sqli/SKILL.md": SKILL},
                    "beta/two": {"LICENSE": "Apache License\nVersion 2.0\n", "notes/SKILL.md": SKILL},
                }),
                "2026-10-24T00:00:00+00:00",
                ROOT,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["written"], 1)
            self.assertEqual(result["duplicates"], 1)
            written = [item for item in result["files"] if item["status"] == "written"][0]
            duplicate = [item for item in result["files"] if item["status"] == "duplicate"][0]
            self.assertEqual(duplicate["kept"], written["dest"])
            self.assertEqual(written["license"], "MIT")
            staged = os.path.join(staging, written["dest"])
            with open(staged, encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("STAGING ONLY", text)
            self.assertIn("license: MIT", text)
            self.assertTrue(os.path.realpath(staged).startswith(os.path.realpath(staging) + os.sep))

    def test_second_run_is_present_not_a_rewrite(self):
        with tempfile.TemporaryDirectory() as staging:
            clone = plant({"alpha/one": {"SKILL.md": SKILL}})
            first = harvest.harvest_sources(["alpha/one"], staging, clone, "t1", ROOT)
            second = harvest.harvest_sources(["alpha/one"], staging, clone, "t2", ROOT)
            self.assertEqual(first["written"], 1)
            self.assertEqual(second["written"], 0)
            self.assertEqual(second["present"], 1)

    def test_every_clone_failing_is_a_broken_harvest(self):
        with tempfile.TemporaryDirectory() as staging:
            result = harvest.harvest_sources(
                ["missing/one", "missing/two"],
                staging,
                plant({}),
                "t",
                ROOT,
            )
            self.assertEqual(result["exit_code"], 1)
            self.assertIn("PIPELINE BROKEN", result["verdict"])
            self.assertEqual(result["written"], 0)
            self.assertEqual(result["failed_sources"], ["missing/one", "missing/two"])

    def test_zero_sources_is_a_broken_harvest(self):
        with tempfile.TemporaryDirectory() as staging:
            result = harvest.harvest_sources([], staging, plant({}), "t", ROOT)
            self.assertEqual(result["exit_code"], 2)

    def test_a_clone_with_no_skill_files_is_a_real_empty_result(self):
        with tempfile.TemporaryDirectory() as staging:
            result = harvest.harvest_sources(
                ["alpha/one"],
                staging,
                plant({"alpha/one": {"README.md": "no skill here\n"}}),
                "t",
                ROOT,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["written"], 0)
            self.assertEqual(result["files"][0]["status"], "no-skill-files")

    def test_refuses_to_write_into_loaded_skill_dirs(self):
        with self.assertRaises(RuntimeError):
            harvest.harvest_sources([], os.path.join(ROOT, "skills", "seeds"), plant({}), "t", ROOT)

    def test_flat_name_cannot_leave_the_staging_directory(self):
        name = harvest.flat_name("owner/repo", "../../etc/passwd/SKILL.md")
        self.assertNotIn("/", name)
        self.assertTrue(name.endswith(".staged.md"))
        with tempfile.TemporaryDirectory() as staging:
            dest = os.path.join(staging, name)
            self.assertTrue(os.path.realpath(dest).startswith(os.path.realpath(staging) + os.sep))

    def test_agpl_is_not_classified_as_gpl(self):
        self.assertEqual(harvest.classify_license("GNU AFFERO GENERAL PUBLIC LICENSE"), "AGPL-3.0")


if __name__ == "__main__":
    unittest.main()
