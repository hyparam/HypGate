"""Regression checks for batching proof failures without losing mutation coverage."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check_mutations as runner


class BatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.keys = [("Function", name) for name in ("f", "g", "unrelated")]
        self.baseline = {key: ("Function", "same spec", "original", "Exec") for key in self.keys}
        self.mutated = dict(self.baseline)
        for key in self.keys[:2]:
            self.mutated[key] = ("Function", "same spec", "mutated", "Exec")
        self.spans = {"test.rs": [(10, 19, self.keys[0]), (20, 29, self.keys[1]), (30, 39, self.keys[2])]}
        self.batch = [(("test.rs", name, "before", "after"), key)
                      for name, key in zip(("first", "second"), self.keys)]

    def run_batch(self, output, mutated=None):
        def apply(work, name, mutations):
            log = work / name / "vir" / "crate-simple.vir"
            log.parent.mkdir(parents=True)
            log.touch()
            return work / name / "src", True

        with patch.object(runner, "apply", side_effect=apply), \
             patch.object(runner, "parse_vir", return_value=(self.mutated if mutated is None else mutated, self.spans)), \
             patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=output, stderr="")), \
             patch.object(runner, "check", side_effect=lambda work, file, name, before, after: name + ": individual") as single:
            reports = runner.check_batch(self.work, self.baseline, 0, self.batch)
        return reports, single

    def test_unrelated_resource_limit_does_not_discard_independent_failures(self):
        reports, single = self.run_batch(
            "error: assertion failed\n --> test.rs:12:1\n"
            "error: precondition not satisfied\n --> test.rs:22:1\n"
            "error: Resource limit exceeded\n --> test.rs:32:1\n")
        self.assertEqual(reports, ["first: rejected by proof", "second: rejected by proof"])
        single.assert_not_called()

    def test_arithmetic_safety_failure_is_a_proof_rejection(self):
        reports, single = self.run_batch(
            "error: possible arithmetic underflow/overflow\n --> test.rs:12:1\n"
            "error: assertion failed\n --> test.rs:22:1\n")
        self.assertEqual(reports, ["first: rejected by proof", "second: rejected by proof"])
        single.assert_not_called()

    def test_resource_limit_is_not_a_proof_failure(self):
        reports, single = self.run_batch(
            "error: assertion failed\n --> test.rs:12:1\n"
            "error: Resource limit exceeded\n --> test.rs:22:1\n")
        self.assertEqual(reports, ["first: rejected by proof", "second: individual"])
        self.assertEqual([call.args[2] for call in single.call_args_list], ["second"])

    def test_unattributed_errors_cannot_reject_a_mutation(self):
        reports, single = self.run_batch("error: assertion failed\n --> test.rs:32:1\n")
        self.assertEqual(reports, ["first: individual", "second: individual"])
        self.assertEqual(single.call_count, 2)

    def test_changed_item_set_splits_then_checks_each_mutation(self):
        mutated = dict(self.mutated)
        mutated[("Function", "extra")] = ("Function", "spec", "body", "Exec")
        reports, single = self.run_batch("error: assertion failed\n --> test.rs:12:1\n", mutated)
        self.assertEqual(reports, ["first: individual", "second: individual"])
        self.assertEqual(single.call_count, 2)

    def test_specification_change_cannot_be_accepted_as_body_only(self):
        mutated = dict(self.mutated)
        mutated[self.keys[0]] = ("Function", "different spec", "mutated", "Exec")
        changed, beyond = runner.local_changes(self.baseline, mutated)
        self.assertEqual(changed, {self.keys[1]})
        self.assertEqual(beyond, {self.keys[0]})

    def test_individual_resource_limit_is_not_a_proof_rejection(self):
        with patch.object(runner, "apply", return_value=(self.work, True)), \
             patch.object(runner.subprocess, "run", return_value=SimpleNamespace(
                 returncode=1, stdout="error: Resource limit exceeded", stderr="")):
            with self.assertRaises(RuntimeError):
                runner.check(self.work, *self.batch[0][0])

    def test_surviving_individual_mutation_fails(self):
        with patch.object(runner, "apply", return_value=(self.work, True)), \
             patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            with self.assertRaises(RuntimeError):
                runner.check(self.work, *self.batch[0][0])


if __name__ == "__main__":
    unittest.main()
