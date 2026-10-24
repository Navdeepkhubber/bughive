import importlib.util
import json
import os
import subprocess
import sys
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
        self.assertEqual(harvest.license_policy("AGPL-3.0"), "skip")
        self.assertEqual(harvest.license_policy("GPL-3.0"), "skip")
        self.assertEqual(harvest.license_policy("MIT"), "permissive")
        self.assertEqual(harvest.license_policy("unspecified"), "flagged")

    def test_copyleft_repo_is_skipped_and_unlicensed_repo_is_flagged(self):
        with tempfile.TemporaryDirectory() as staging:
            result = harvest.harvest_sources(
                ["copy/left", "no/license"],
                staging,
                plant({
                    "copy/left": {
                        "LICENSE": "GNU AFFERO GENERAL PUBLIC LICENSE\n",
                        "SKILL.md": SKILL,
                    },
                    "no/license": {"SKILL.md": SKILL + "unique marker\n"},
                }),
                "t",
                ROOT,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["license_skipped"], ["copy/left"])
            self.assertEqual(result["flagged_sources"], ["no/license"])
            self.assertEqual(result["written"], 1)
            self.assertEqual(result["files"][0]["status"], "license-skipped")
            names = [name for name in os.listdir(staging) if name.endswith(".staged.md")]
            self.assertEqual(names, [harvest.flat_name("no/license", "SKILL.md")])
            with open(os.path.join(staging, names[0]), encoding="utf-8") as handle:
                self.assertIn("license: unspecified", handle.read())

    def test_dry_run_lists_configured_sources_and_does_not_clone(self):
        done = subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "harvest-bb-skills.py"), "--dry-run"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        payload = json.loads(done.stdout)
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["sources"], [
            "ctahok/hermes-bug-bounty-skills",
            "0x002132/skills-bugbounty",
            "Aetherdz/huntpack",
            "murraywu/Bug-Bounty-Skills",
            "Gabson0x/bountyforge",
        ])

    def test_author_and_commit_land_in_the_header(self):
        with tempfile.TemporaryDirectory() as staging:
            result = harvest.harvest_sources(
                ["ada/notes"],
                staging,
                git_clone(SKILL, "Ada Lovelace"),
                "2026-10-24T00:00:00+00:00",
                ROOT,
            )
            self.assertEqual(result["written"], 1)
            with open(os.path.join(staging, result["files"][0]["dest"]), encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("author: Ada Lovelace", text)
            self.assertRegex(text, r"commit: [0-9a-f]{40};")
            self.assertIn("license: MIT", text)

    def test_unchanged_body_backfills_author_without_a_new_write(self):
        with tempfile.TemporaryDirectory() as staging:
            name = harvest.flat_name("ada/notes", "SKILL.md")
            with open(os.path.join(staging, name), "w", encoding="utf-8") as handle:
                handle.write(
                    "<!-- harvested: ada/notes/SKILL.md on 2026-10-01T00:00:00+00:00 -->\n"
                    "<!-- STAGING ONLY -- old header -->\n\n"
                    + SKILL
                )
            result = harvest.harvest_sources(
                ["ada/notes"],
                staging,
                git_clone(SKILL, "Ada Lovelace"),
                "2026-10-24T00:00:00+00:00",
                ROOT,
            )
            self.assertEqual(result["written"], 0)
            self.assertEqual(result["files"][0]["status"], "provenance")
            with open(os.path.join(staging, name), encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("author: Ada Lovelace", text)
            self.assertIn("on 2026-10-01T00:00:00+00:00", text)
            self.assertTrue(text.endswith(SKILL) or SKILL in text)


def git_clone(body, author):
    def clone(repo, dest):
        os.makedirs(dest, exist_ok=True)
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": author,
            "GIT_AUTHOR_EMAIL": "ada@example.com",
            "GIT_COMMITTER_NAME": author,
            "GIT_COMMITTER_EMAIL": "ada@example.com",
        }
        subprocess.run(["git", "init", dest], check=True, capture_output=True)
        with open(os.path.join(dest, "LICENSE"), "w", encoding="utf-8") as handle:
            handle.write("MIT License\n\nPermission is hereby granted\n")
        with open(os.path.join(dest, "SKILL.md"), "w", encoding="utf-8") as handle:
            handle.write(body)
        subprocess.run(["git", "-C", dest, "add", "LICENSE", "SKILL.md"], check=True, capture_output=True)
        subprocess.run(["git", "-C", dest, "commit", "-m", "add skill"], check=True, capture_output=True, env=env)
        return True

    return clone


if __name__ == "__main__":
    unittest.main()
