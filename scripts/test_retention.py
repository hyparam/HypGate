import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

loader = importlib.machinery.SourceFileLoader("retention", str(Path(__file__).with_name("hypgate-retain")))
spec = importlib.util.spec_from_loader(loader.name, loader)
retention = importlib.util.module_from_spec(spec)
loader.exec_module(retention)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.archive = Path(self.temp.name)
        self.now = 100 * retention.DAY_NS

    def tearDown(self):
        self.temp.cleanup()

    def log(self, name, age):
        path = self.archive / name
        header = b"SGLOG001" + bytes(16)
        path.write_bytes(header + hashlib.sha256(header).digest())
        timestamp = self.now - age * retention.DAY_NS
        os.utime(path, ns=(timestamp, timestamp))
        return path

    def test_preview_then_delete_only_expired_valid_archives(self):
        old = self.log("session-old.log", 31)
        boundary = self.log("session-boundary.log", 30)
        young = self.log("session-young.log", 29)
        unrelated = self.log("checkpoint.json", 31)
        invalid = self.log("session-invalid.log", 31)
        invalid.write_bytes(b"not a log")
        os.utime(invalid, ns=(0, 0))
        rows = retention.prune(self.archive, 30, now_ns=self.now)
        self.assertEqual([r["file"] for r in rows if r["action"] == "would_delete"], [old.name])
        self.assertTrue(old.exists())
        rows = retention.prune(self.archive, 30, apply=True, now_ns=self.now)
        self.assertFalse(old.exists())
        self.assertTrue(all(p.exists() for p in [boundary, young, unrelated, invalid]))
        self.assertEqual([r["action"] for r in rows], ["skip", "deleted"])

    def test_links_directories_and_future_files_are_not_deleted(self):
        outside = self.log("unrelated.log", 31)
        (self.archive / "session-link.log").symlink_to(outside)
        os.link(outside, self.archive / "session-hardlink.log")
        (self.archive / "session-dir.log").mkdir()
        self.log("session-future.log", -1)
        self.assertEqual(retention.prune(self.archive, 30, apply=True, now_ns=self.now), [])
        self.assertTrue(outside.exists())

    def test_rejects_public_directory_symlink_root_and_invalid_age(self):
        with self.assertRaises(ValueError):
            retention.prune(self.archive, 0)
        self.archive.chmod(0o755)
        with self.assertRaises(ValueError):
            retention.prune(self.archive, 30)
        self.archive.chmod(0o700)
        link = self.archive / "alias"
        link.symlink_to(self.archive, target_is_directory=True)
        with self.assertRaises(OSError):
            retention.prune(link, 30)


if __name__ == "__main__":
    unittest.main()
