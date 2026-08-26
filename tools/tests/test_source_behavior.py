from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "catalog"))

import source_behavior


SOURCE = b"""
public sealed class Buyer {
    public async Task Run() {
        var prices = await httpClient.GetStringAsync("https://universalis.app/api/v2/Europe/5333");
        var selected = prices.OrderBy(x => x.Price).First();
        if (!NearMarketBoard()) {
            await navmesh.PathfindAndMoveTo(target);
        }
        await Task.Delay(500);
        marketBoard.Purchase(selected);
    }

    private async void OnUpdate() {
        marketBoard.Purchase(selected);
    }

    public void Enable() {
        Framework.Update += OnUpdate;
    }
}
"""


class SourceBehaviorTests(unittest.TestCase):
    def result(self):
        return source_behavior.collect({"Buyer.cs": len(SOURCE)}, lambda path: SOURCE)

    def test_retains_service_and_primitive_operations(self):
        result = self.result()
        operations = result["operations"]
        market = [x for x in operations if x["operation"] == "network.http.request"]
        self.assertEqual(1, len(market))
        self.assertEqual("ffxiv.universalis", market[0]["serviceId"])
        self.assertIn("ffxiv.market-data", market[0]["serviceCapabilities"])
        self.assertTrue(market[0]["serviceRegistryRevision"].startswith("services-v1-"))
        self.assertTrue(market[0]["semanticApiRegistryRevision"].startswith("semantic-apis-v1-"))
        self.assertEqual("httpClient", market[0]["receiver"])
        self.assertEqual("GetStringAsync", market[0]["member"])
        self.assertTrue(any(x["operation"] == "data.select" for x in operations))
        self.assertTrue(any(x["operation"] == "game.character.move" for x in operations))
        self.assertTrue(any(x["operation"] == "game.marketboard.purchase" for x in operations))

    def test_retains_relative_time_condition_and_data_flow(self):
        result = self.result()
        self.assertTrue(any(x["kind"] == "if" and "<redacted>" not in x["normalizedExpression"] for x in result["conditions"]))
        purchase_edges = [x for x in result["flowEdges"] if x["toOperation"] == "game.marketboard.purchase"]
        self.assertTrue(any(x["minimumDelayMs"] == 500 for x in purchase_edges))
        self.assertTrue(any(
            x["toOperation"] == "game.marketboard.purchase" and "ffxiv.market-data" in x["fromServiceCapabilities"]
            for x in result["dataFlow"]
        ))

    def test_event_trigger_is_linked_to_handler_first_operation(self):
        result = self.result()
        self.assertTrue(any(x["kind"] == "event" and x["handler"] == "OnUpdate" for x in result["triggers"]))
        self.assertTrue(any(
            x["relation"] == "triggers" and x["fromOperation"] == "trigger.event"
            and x["toOperation"] == "game.marketboard.purchase"
            for x in result["flowEdges"]
        ))

    def test_periodic_trigger_links_to_operation_after_timer_registration(self):
        source = b"""
public sealed class Buyer {
    public async Task Tick() {
        logger.Info(\"before\");
        var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (await timer.WaitForNextTickAsync()) {
            marketBoard.Purchase(item);
        }
    }
}
"""
        result = source_behavior.collect({"Buyer.cs": len(source)}, lambda path: source)
        periodic = next(row for row in result["triggers"] if row["kind"] == "periodic")
        self.assertEqual(5000, periodic["periodMs"])
        edge = next(row for row in result["flowEdges"] if row["fromOperation"] == "trigger.periodic")
        self.assertEqual("triggers", edge["relation"])
        self.assertEqual("game.marketboard.purchase", edge["toOperation"])
        self.assertEqual(5000, edge["minimumDelayMs"])



if __name__ == "__main__":
    unittest.main()
