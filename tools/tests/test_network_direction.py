from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

import common

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tools" / "catalog"
SECURITY = ROOT / "tools" / "security"
for path in (CATALOG, SECURITY):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import semantic_registry  # noqa: E402
import source_behavior  # noqa: E402
from security_endpoint_inventory import endpoint_candidates, endpoint_summary  # noqa: E402
import srl  # noqa: E402


class NetworkDirectionTests(unittest.TestCase):
    def test_endpoint_literals_retain_outbound_or_unknown_direction(self) -> None:
        concrete = endpoint_candidates(
            'var url = "https://universalis.app/api/v2/Europe/5333";',
            "source:Plugin.cs",
        )[0]
        self.assertTrue(concrete["concreteDestinationEvidence"])
        self.assertEqual("outbound", concrete["trafficDirection"])

        reference = endpoint_candidates(
            'var docs = "https://github.com/dalagab/omega/blob/main/README.md";',
            "source:README.cs",
        )[0]
        self.assertFalse(reference["concreteDestinationEvidence"])
        self.assertEqual("unknown", reference["trafficDirection"])

        summary = endpoint_summary([concrete, reference], True)
        self.assertEqual({"outbound": 1, "unknown": 1}, summary["trafficDirectionCounts"])
        by_host = {row["host"]: row for row in summary["hosts"]}
        self.assertEqual(["outbound"], by_host["universalis.app"]["trafficDirections"])

    def test_semantic_api_registry_declares_all_three_network_roles(self) -> None:
        http = semantic_registry.match_source_call("httpClient", "GetStringAsync")
        listener = semantic_registry.match_source_call("tcpListener", "AcceptTcpClientAsync")
        websocket = semantic_registry.match_source_call("clientWebSocket", "ConnectAsync")
        self.assertEqual("outbound", http["attributes"]["trafficDirection"])
        self.assertEqual("inbound", listener["attributes"]["trafficDirection"])
        self.assertEqual("bidirectional", websocket["attributes"]["trafficDirection"])

    def test_invalid_registry_direction_is_rejected(self) -> None:
        doc = json.loads((ROOT / "security-definitions" / "semantic-apis" / "registry.json").read_text(encoding="utf-8"))
        doc["sourceMatchers"][0]["attributes"]["trafficDirection"] = "sideways"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "registry.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid trafficDirection"):
                semantic_registry.load_api_registry(path)

    def test_source_operations_retain_outbound_inbound_and_bidirectional_roles(self) -> None:
        source = b'''
public sealed class NetworkRoles {
    public async Task Run() {
        var prices = await httpClient.GetStringAsync("https://universalis.app/api/v2/Europe/5333");
        tcpListener.AcceptTcpClientAsync();
        await clientWebSocket.ConnectAsync(uri, cancellationToken);
    }
}
'''
        result = source_behavior.collect({"NetworkRoles.cs": len(source)}, lambda path: source)
        by_operation = {row["operation"]: row for row in result["operations"]}
        self.assertEqual("outbound", by_operation["network.http.request"]["trafficDirection"])
        self.assertEqual("inbound", by_operation["network.listener.accept"]["trafficDirection"])
        self.assertEqual("bidirectional", by_operation["network.websocket.session"]["trafficDirection"])

    def test_srl_can_reason_over_direction_without_scanner_conclusions(self) -> None:
        rule = srl.compile_yaml_text('''
schema: omega.sigmascope.rule.v1
id: example.network.duplex-session
kind: observation
status: experimental
requires: [sourceOperations]
selectors:
  duplex:
    collection: sourceOperations
    where:
      operation: {equals-ci: network.websocket.session}
      trafficDirection: {equals-ci: bidirectional}
condition: duplex
emit:
  fact: network.session.bidirectional
  confidence: high
  title: Bidirectional network session primitive observed
''')
        result = srl.evaluate_ruleset(rule, {
            "sourceOperations": [{
                "operationId": "op-1",
                "operation": "network.websocket.session",
                "trafficDirection": "bidirectional",
                "origin": "source",
            }]
        })
        self.assertEqual(["network.session.bidirectional"], result["facts"])


if __name__ == "__main__":
    unittest.main()
