"""Offline regressions for live-kernel evidence classification."""

import argparse
import importlib.util
import json
import os
import pathlib
import re
import tempfile
import unittest
from unittest.mock import Mock, patch


source = pathlib.Path(os.environ.get("KNDBGX_HARNESS_SOURCE", pathlib.Path(__file__).with_name("test-live-kernel.py")))
spec = importlib.util.spec_from_file_location("live_harness", source)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


class HarnessTests(unittest.TestCase):
    def test_submission_receipt_does_not_wait_for_an_engine_echo(self):
        session = live.Session.__new__(live.Session)
        session.sequence = 0
        session.read = Mock(return_value="old output\n")
        session.send = Mock()
        receipt = "1: kd> [job] " + "a" * 32 + "\n"
        session.wait = lambda predicate, timeout: predicate("old output\n" + receipt)
        self.assertEqual(session.run("submit diagnose analyze"), receipt)
        self.assertIsNone(session.run("help submit"))
        self.assertFalse(live.has_submission_receipt("submit diagnose analyze", '!kndbgx submit raw .echo "[job] ' + 'a' * 32 + '"'))
        self.assertFalse(live.has_submission_receipt("submit diagnose analyze", "[job] short\n"))

    def test_context_rows_allow_only_bounded_prefix_differences(self):
        bounded = {"state": "Partial", "result": {"coverage": {"complete": False, "stopReason": "GlobalWalkBudget"}}}
        complete = {"state": "Success", "result": {"coverage": {"complete": True}}}
        rows = [{"object": "1"}, {"object": "2"}]
        self.assertTrue(live.equivalent_bounded_rows(rows[:1], bounded, rows, complete))
        self.assertTrue(live.equivalent_bounded_rows(rows, complete, rows[:1], bounded))
        self.assertFalse(live.equivalent_bounded_rows(rows[:1], complete, rows, complete))
        self.assertFalse(live.equivalent_bounded_rows([], bounded, rows, complete))
        self.assertFalse(live.equivalent_bounded_rows([{"object": "3"}], bounded, rows, complete))
        unreadable = {"state": "Partial", "result": {"coverage": {"complete": False, "stopReason": "Unreadable"}}}
        self.assertFalse(live.equivalent_bounded_rows(rows[:1], unreadable, rows, complete))

    def test_contract_uses_registry_names_instead_of_a_fixed_count(self):
        expected = json.loads((source.resolve().parents[1] / "docs/command-contract.json").read_text(encoding="utf-8"))
        session = Mock()
        self.harness.only = re.compile("^contract-json$")
        session.run.return_value = json.dumps(expected)
        self.harness.phase_session(session)
        self.assertTrue(self.harness.checks["contract-json"]["ok"])
        expected[-1]["name"] = "unexpected-command"
        session.run.return_value = json.dumps(expected)
        self.harness.phase_session(session)
        self.assertFalse(self.harness.checks["contract-json"]["ok"])

    def test_remote_process_collection_requires_target_provenance(self):
        session = Mock()
        self.harness.only = re.compile("^target-backed:hiddenproc")
        for provenance, expected in (("HostToolhelp", False), ("TargetMemory:PspCidTable", True)):
            with self.subTest(provenance=provenance):
                session.job.return_value = ("", {"state": "Success", "result": {"provenance": {"source": provenance}}})
                self.harness.phase_host_collectors_remote(session)
                self.assertEqual(self.harness.checks["target-backed:hiddenproc-provenance"]["ok"], expected)

    def test_context_defaults_reject_empty_success_rows(self):
        session = Mock()
        session.native.return_value = ("Evaluate expression: 1 = ffff8000`00001000\n"
                                       "Evaluate expression: 2 = ffff8000`00002000\nrip=ffff800000003000")
        session.job.return_value = ("", {"state": "Success", "resultId": "a" * 64})
        session.rows.return_value = []
        self.harness.phase_context_defaults(session)
        self.assertFalse(self.harness.checks["current-context-defaults"]["ok"])

    def test_context_defaults_reject_wrong_current_thread(self):
        session = Mock()
        session.native.return_value = ("Evaluate expression: 1 = ffff8000`00001000\n"
                                       "Evaluate expression: 2 = ffff8000`00002000\nrip=ffff800000003000")
        session.job.return_value = ("", {"state": "Success", "resultId": "a" * 64})
        wrong_thread = [{"ethread": "0xffff800000009000"}]
        process = [{"eprocess": "0xffff800000002000"}]
        token = [{"ethread": "0xffff800000001000", "selection": "CurrentThreadEffectiveToken"}]
        session.rows.side_effect = [wrong_thread, wrong_thread, process, process, token, [], []]
        self.harness.phase_context_defaults(session)
        self.assertFalse(self.harness.checks["current-context-defaults"]["ok"])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.args = argparse.Namespace(evidence=pathlib.Path(self.directory.name), resume=False,
                                       budget=60, only=None, verbose=False)
        self.harness = live.Harness(self.args)

    def test_error_output_is_not_success(self):
        for state in ("EngineError", "InternalFault", "Cancelled", "IOError", "InvalidInput", "Running", None):
            with self.subTest(state=state):
                self.assertFalse(self.harness.terminal_ok({"state": state, "output": "host output"})[0])

    def test_job_requires_expected_terminal_state(self):
        for state in ("Cancelled", "IOError", "InvalidInput", "Running", None):
            with self.subTest(state=state):
                session = Mock()
                session.job.return_value = ("", {"state": state})
                self.harness.job_check(session, "job", "!idt")
                self.assertFalse(self.harness.checks["job"]["ok"])

    def test_negative_check_can_explicitly_accept_invalid_input(self):
        session = Mock()
        session.job.return_value = ("", {"state": "InvalidInput"})
        self.harness.job_check(session, "usage", "!drvobj", states=("InvalidInput",))
        self.assertTrue(self.harness.checks["usage"]["ok"])

    def test_native_context_probe_rejects_invalid_output(self):
        for output in ("", "Syntax error", "rip=1234", "Evaluate expression: 0 = 0\nrip=1234"):
            self.assertIsNone(live.native_context_signature(output))
        self.assertNotIn(".thread", live.NATIVE_CONTEXT_PROBE)
        self.assertNotIn(".process", live.NATIVE_CONTEXT_PROBE)

    def test_cpu_context_change_fails_even_with_success_result(self):
        before = "Evaluate expression: 1 = ffff8000`00001000\nEvaluate expression: 2 = ffff8000`00002000\nrip=ffff800000003000"
        after = before.replace("00001000", "00004000")
        session = Mock()
        session.native.side_effect = [before, after]
        session.job.return_value = ("", {"state": "Success"})
        self.harness.job_context_check(session, "cpu", "!cr")
        self.assertTrue(self.harness.checks["cpu"]["ok"])
        self.assertFalse(self.harness.checks["cpu-context-preserved"]["ok"])

    def test_native_context_rejects_null_and_malformed_addresses(self):
        valid = "Evaluate expression: 1 = ffff8000`00001000\nEvaluate expression: 2 = ffff8000`00002000\nrip=ffff800000003000"
        for value in ("0", "00000000`00000000", "0xffff800000001000", "ffff800000001000oops",
                      "1ffff800000001000", "`", "ffff8000``00001000", "1000",
                      "feff800000001000", "ffff800000001001"):
            with self.subTest(value=value):
                self.assertIsNone(live.native_context_signature(valid.replace("ffff8000`00001000", value)))
        for value in ("0", "ffff800000003000oops", "1ffff800000003000", "0100000000003000"):
            with self.subTest(rip=value):
                self.assertIsNone(live.native_context_signature(valid.replace("ffff800000003000", value)))

    def test_native_context_accepts_full_addresses_and_user_rip(self):
        output = "Evaluate expression: -1 = ffff8000`00001000\r\nEvaluate expression: -2 = ff80000000002000\r\nrip=00007ffa12345678\r\n"
        self.assertEqual(live.native_context_signature(output),
                         (0xffff800000001000, 0xff80000000002000, 0x00007ffa12345678))

    def test_identical_null_probes_cannot_confirm_cpu_context(self):
        session = Mock()
        session.native.return_value = "Evaluate expression: 0 = 0\nEvaluate expression: 0 = 0\nrip=0"
        session.job.return_value = ("", {"state": "Success"})
        self.harness.job_context_check(session, "cpu", "!cr")
        self.assertFalse(self.harness.checks["cpu-context-preserved"]["ok"])

    def test_resume_rechecks_failed_or_missing_cpu_context(self):
        for name in ("job-cr", "job-idt", "job-msrcheck"):
            for context_ok, selector in ((False, name), (False, name + "-context-preserved"),
                                         (None, name + "(?:-context-preserved)?")):
                with self.subTest(name=name, context_ok=context_ok, selector=selector):
                    saved = [{"name": name, "ok": True, "evidenceVersion": live.EVIDENCE_VERSION}]
                    if context_ok is not None:
                        saved.append({"name": name + "-context-preserved", "ok": context_ok,
                                      "evidenceVersion": live.EVIDENCE_VERSION})
                    self.harness.store_path.write_text(json.dumps(saved), encoding="utf-8")
                    self.args.resume = True
                    self.args.only = "^" + selector + "$"
                    resumed = live.Harness(self.args)
                    session = Mock()
                    session.native.return_value = "Evaluate expression: 1 = ffff800000001000\nEvaluate expression: 2 = ffff800000002000\nrip=ffff800000003000"
                    session.job.return_value = ("", {"state": "Partial"})
                    resumed.phase_kernel_collectors(session)
                    session.job.assert_called_once()
                    self.assertEqual(session.native.call_count, 2)
                    self.assertTrue(resumed.checks[name + "-context-preserved"]["ok"])

    def test_resume_skips_cpu_only_when_both_checks_passed(self):
        for name in ("job-cr", "job-cr-context-preserved"):
            self.harness.record(name, True)
        self.args.resume = True
        self.args.only = "^job-cr(?:-context-preserved)?$"
        resumed = live.Harness(self.args)
        session = Mock()
        resumed.phase_kernel_collectors(session)
        session.job.assert_not_called()
        session.native.assert_not_called()

    def test_cpu_context_only_filter_runs_its_collector(self):
        self.args.only = "^job-idt-context-preserved$"
        harness = live.Harness(self.args)
        harness.job_context_check = Mock()
        harness.phase_kernel_collectors(Mock())
        self.assertEqual(harness.job_context_check.call_count, 1)
        self.assertEqual(harness.job_context_check.call_args.args[1:], ("job-idt", "!idt"))

    def test_device_operand_comes_from_retained_driver_rows(self):
        self.args.only = "^job-drvobj-disk$"
        harness = live.Harness(self.args)
        session = Mock()
        session.job.return_value = ("", {"state": "Partial", "resultId": "driver", "result": {"rows": []}})
        session.rows.return_value = [{"kind": "Driver", "firstDevice": None},
                                     {"kind": "Driver", "firstDevice": "0x0000000000000000"},
                                     {"kind": "Driver", "firstDevice": "0xffff800000001000"}]
        harness.phase_kernel_collectors(session)
        self.assertEqual(harness.facts["diagnostic-operands"]["devstack"], "0xffff800000001000")
        session.rows.assert_called_once()

    def test_device_partial_requires_an_observed_device(self):
        self.args.only = "^job-devstack"
        for rows, expected in (([], False), ([{"kind": "Device"}], True)):
            with self.subTest(rows=rows):
                harness = live.Harness(self.args)
                harness.facts["diagnostic-operands"] = {"devstack": "0xffff800000001000"}
                session = Mock()
                session.native.return_value = "Evaluate expression: 1 = ffff800000001000\nEvaluate expression: 2 = ffff800000002000\nrip=ffff800000003000"
                session.job.return_value = ("", {"state": "Partial", "resultId": "device"})
                session.rows.return_value = rows
                harness.phase_kernel_addresses(session)
                self.assertEqual(harness.checks["job-devstack-observed-device"]["ok"], expected)
                self.assertTrue(harness.checks["job-devstack-context-preserved"]["ok"])

    def test_cpu_context_requires_two_valid_unchanged_probes(self):
        valid = "Evaluate expression: 1 = ffff8000`00001000\nEvaluate expression: 2 = ffff8000`00002000\nrip=ffff800000003000"
        for output, expected in ((valid, True), ("Syntax error", False)):
            session = Mock()
            session.native.return_value = output
            session.job.return_value = ("", {"state": "Partial"})
            self.harness.job_context_check(session, "cpu", "!idt")
            self.assertEqual(self.harness.checks["cpu-context-preserved"]["ok"], expected)

    def sync_session(self, state, text="observation", matching_receipt=True):
        identity = "a" * 64
        page = {"Schema": "kndbgx.model.v1", "ResultId": identity if matching_receipt else "b" * 64,
                "Metadata": {"status": state}}
        session = Mock()
        session.run.side_effect = [text + "\n[result] " + identity, json.dumps(page, separators=(",", ":"))]
        return session

    def test_sync_marker_cannot_hide_failure_state(self):
        for state in ("EngineError", "InternalFault", "Cancelled", "IOError", "InvalidInput", "Unavailable", None):
            with self.subTest(state=state):
                session = self.sync_session(state, "[memory] partial output")
                self.harness.sync_check(session, "sync", "db nt L4", must=("[memory]",))
                self.assertFalse(self.harness.checks["sync"]["ok"])

    def test_sync_success_requires_its_matching_receipt(self):
        self.harness.sync_check(self.sync_session("Success", matching_receipt=False), "sync", "db nt L4")
        self.assertFalse(self.harness.checks["sync"]["ok"])
        self.harness.sync_check(self.sync_session("Success"), "sync", "db nt L4")
        self.assertTrue(self.harness.checks["sync"]["ok"])

    def test_sync_missing_receipt_and_empty_text_fail(self):
        for output in ("", "no crash"):
            session = Mock()
            session.run.return_value = output
            self.harness.sync_check(session, "sync", "db nt L4")
            self.assertFalse(self.harness.checks["sync"]["ok"])

    def test_sync_refusal_requires_explicit_expected_state(self):
        self.harness.sync_check(self.sync_session("IOError"), "missing-etl", "etl-import absent.etl",
                                states=("IOError",))
        self.assertTrue(self.harness.checks["missing-etl"]["ok"])

    def test_detached_command_requires_expected_text(self):
        session = Mock()
        session.run.return_value = "KNDbgX 0.2.0-preview.7"
        self.harness.sync_check(session, "version", "version", must=("KNDbgX 0.2.0",), require_result=False)
        self.assertTrue(self.harness.checks["version"]["ok"])
        session.run.return_value = "unrelated output"
        self.harness.sync_check(session, "version", "version", must=("KNDbgX 0.2.0",), require_result=False)
        self.assertFalse(self.harness.checks["version"]["ok"])

    def test_timeout_remains_failed_and_resumable(self):
        session = Mock()
        session.submit.return_value = ("", "job-id")
        session.poll.side_effect = TimeoutError()
        session.native.side_effect = TimeoutError()
        with self.assertRaises(live.EngineMonopolized):
            self.harness.diag_job(session, "diagnose-stacks", "diagnose stacks", timeout=0)
        self.assertFalse(self.harness.checks["diagnose-stacks"]["ok"])
        self.assertNotIn("diagnose-stacks-engine-wait", self.harness.checks)
        self.args.resume = True
        resumed = live.Harness(self.args)
        self.assertTrue(resumed.wanted("diagnose-stacks"))

    def test_live_job_poll_yields_between_nonterminal_results(self):
        session = live.Session.__new__(live.Session)
        session.process = Mock()
        session.process.poll.return_value = None
        session.run = Mock(side_effect=[
            '{"jobId":"owned","state":"Running"}',
            '{"jobId":"owned","state":"Success","result":{}}',
        ])
        with patch.object(live.time, "sleep") as sleep:
            self.assertEqual(session.poll("owned")["state"], "Success")
            sleep.assert_called_once_with(1.0)

    def test_legacy_success_cannot_skip_corrected_validation(self):
        for version in (None, 5):
            self.harness.store_path.write_text(json.dumps([
                {"name": "diagnose-errrec", "ok": True, "evidenceVersion": version}
            ]), encoding="utf-8")
            self.args.resume = True
            resumed = live.Harness(self.args)
            self.assertTrue(resumed.wanted("diagnose-errrec"))

    def test_process_address_is_not_a_typed_object_fixture(self):
        session = Mock()
        session.run.return_value = '\n'.join([
            '{"kind":"DiagnosticRecipe","name":"errrec","operand":"hex-address"}',
            '{"kind":"DiagnosticRecipe","name":"wdf-driver","operand":"module"}',
            '{"kind":"DiagnosticRecipe","name":"pte","operand":"hex-address"}',
            '{"kind":"DiagnosticRecipe","name":"verifier","operand":"optional-module"}',
        ])
        self.harness.facts["eprocess"] = "0xffff800000001000"
        self.harness.diag_job = Mock(return_value=("", {"state": "Success"}))
        self.harness.phase_diagnostics(session)
        commands = [call.args[2] for call in self.harness.diag_job.call_args_list]
        self.assertEqual(commands, ["diagnose pte 0xffff800000001000", "diagnose verifier"])
        self.assertTrue(self.harness.checks["diagnose-errrec"]["skipped"])
        self.assertTrue(self.harness.checks["diagnose-wdf-driver"]["skipped"])

    def test_verified_recipe_operand_is_used(self):
        session = Mock()
        session.run.return_value = '{"kind":"DiagnosticRecipe","name":"irp","operand":"hex-address"}'
        self.harness.facts["diagnostic-operands"] = {"irp": "0xffff800000002000"}
        self.harness.diag_job = Mock(return_value=("", {"state": "Success"}))
        self.harness.phase_diagnostics(session)
        self.assertEqual(self.harness.diag_job.call_args.args[2], "diagnose irp 0xffff800000002000")

    def test_compound_probe_cannot_inject_a_native_write(self):
        session = Mock()
        identity = "a" * 64
        session.run.side_effect = [
            '[memory] cannot evaluate address: nt; .echo KN_COMPOUND_SENTINEL\n[result] ' + identity,
            json.dumps({"Schema": "fixture", "ResultId": identity, "Metadata": {"status": "InvalidInput"}}),
        ]
        self.harness.wanted = lambda name: name == "compound-refused"
        self.harness.phase_negatives(session)
        self.assertEqual(session.run.call_args_list[0].args[0], 'db "nt; .echo KN_COMPOUND_SENTINEL" L4')
        self.assertTrue(self.harness.checks["compound-refused"]["ok"])

    def test_compound_rejection_requires_a_matching_invalid_input_result(self):
        identity = "a" * 64
        for status, result_id in (("Success", identity), ("InternalFault", identity), ("InvalidInput", "b" * 64)):
            with self.subTest(status=status, result_id=result_id):
                session = Mock()
                session.run.side_effect = ["InvalidInput: invalid address\n[result] " + identity,
                    json.dumps({"Schema": "fixture", "ResultId": result_id, "Metadata": {"status": status}})]
                self.harness.wanted = lambda name: name == "compound-refused"
                self.harness.phase_negatives(session)
                self.assertFalse(self.harness.checks["compound-refused"]["ok"])
        session = Mock()
        session.run.return_value = "InvalidInput: no retained result"
        self.harness.phase_negatives(session)
        self.assertFalse(self.harness.checks["compound-refused"]["ok"])

    def test_resume_rechecks_compound_rejection(self):
        self.harness.store_path.write_text(json.dumps([{"name": "compound-refused", "ok": True,
            "evidenceVersion": live.EVIDENCE_VERSION}]), encoding="utf-8")
        self.args.resume = True
        resumed = live.Harness(self.args)
        self.assertTrue(resumed.wanted("compound-refused"))

    def test_complete_preview_is_valid_without_a_global_write_switch(self):
        session = Mock()
        session.run.return_value = ("[plan] complete preview; no target bytes written\n"
                                    "[plan.approval] approve " + "a" * 48 + " " + "b" * 48)
        self.harness.wanted = lambda name: name == "plan-writable-range-validation"
        self.harness.phase_mutation(session)
        session.run.assert_called_once_with("plan eb nt 90")
        self.assertTrue(self.harness.checks["plan-writable-range-validation"]["ok"])

    def test_same_value_requires_a_successful_verified_approval_receipt(self):
        receipt = {"schema": "kndbgx.result.v2", "commandId": "ed", "status": "Success", "coverage": {"complete": True,
                   "stopReason": "AppliedAndVerified", "expectedEntries": "4", "readEntries": "4", "decodedEntries": "4"},
                   "rows": [{"requestedBytes": "4", "appliedBytes": "4", "verified": True, "status": "Success"}]}
        for change in [{}, {"status": "InvalidInput", "error": {"message": "UnknownPlanOrApprovalToken"}},
                       {"status": "Partial"}, {"rows": []}, {"coverage": {"complete": False}},
                       {"rows": [{"requestedBytes": "4", "appliedBytes": "2", "verified": True, "status": "Partial"}]},
                       {"rows": [{"requestedBytes": "4", "appliedBytes": "4", "verified": False, "status": "Success"}]}]:
            with self.subTest(change=change):
                session = Mock()
                session.run.side_effect = ["ffff8000`00001000 000065f4",
                    "[plan.approval] approve " + "a" * 48 + " " + "b" * 48,
                    json.dumps({**receipt, **change}, separators=(",", ":")), "ffff8000`00001000 000065f4"]
                self.harness.wanted = lambda name: name == "plan-approve-same-value"
                self.harness.phase_mutation(session)
                self.assertEqual(self.harness.checks["plan-approve-same-value"]["ok"], not change)

    def test_same_value_without_an_approval_receipt_is_not_success(self):
        session = Mock()
        session.run.side_effect = ["ffff8000`00001000 000065f4",
            "[plan.approval] approve " + "a" * 48 + " " + "b" * 48,
            "[result] " + "c" * 64, "ffff8000`00001000 000065f4"]
        self.harness.wanted = lambda name: name == "plan-approve-same-value"
        self.harness.phase_mutation(session)
        self.assertFalse(self.harness.checks["plan-approve-same-value"]["ok"])

    def test_resume_discards_successes_from_before_verified_approval_checks(self):
        self.harness.store_path.write_text(json.dumps([{"name": "plan-approve-same-value", "ok": True,
            "evidenceVersion": 7}]), encoding="utf-8")
        self.args.resume = True
        resumed = live.Harness(self.args)
        self.assertTrue(resumed.wanted("plan-approve-same-value"))

    def test_acknowledged_raw_requires_no_global_policy_command(self):
        session = Mock()
        session.submit.return_value = ("Windows Kernel Version fixture", None)
        self.harness.wanted = lambda name: name == "raw-acknowledged"
        self.harness.phase_policy(session)
        session.submit.assert_called_once_with("raw --ack-effects vertarget")
        session.run.assert_not_called()
        self.assertTrue(self.harness.checks["raw-acknowledged"]["ok"])

    def test_memory_output_does_not_prove_compound_rejection(self):
        session = Mock()
        session.run.return_value = "[memory] start=ffff800000001000 length=0x4 read=0x4"
        self.harness.wanted = lambda name: name == "compound-refused"
        self.harness.phase_negatives(session)
        self.assertFalse(self.harness.checks["compound-refused"]["ok"])


if __name__ == "__main__":
    unittest.main()
