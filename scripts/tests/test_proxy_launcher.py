from html.parser import HTMLParser
from pathlib import Path
import unittest


class LauncherParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            self.links.append(attrs.get("href"))
        if tag == "script":
            self.scripts.append(attrs)


class ProxyLauncherTest(unittest.TestCase):
    def test_dashboard_launches_authenticated_sources_without_admin_requests(self):
        page = (Path(__file__).resolve().parents[2] / "static/index.html").read_text()
        parsed = LauncherParser()
        parsed.feed(page)
        self.assertEqual(["https://search.rclabs.uk/sources/proxy"], parsed.links)
        self.assertEqual([], parsed.scripts)
        self.assertIn("Atheros Search", page)
        self.assertNotIn("localStorage", page)
        self.assertNotIn("/stats/live", page)


if __name__ == "__main__":
    unittest.main()
