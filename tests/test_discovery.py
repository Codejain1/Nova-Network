"""
Tests for evidence-based agent discovery — DiscoveryQuery, CapabilityStats,
and CapabilityProfile.

Covers:
  - DiscoveryQuery: default params, fluent builder methods, to_params() output
  - describe() produces human-readable summary
  - with_capability() clamps min_logs to at least 1, min_evidenced to >= 0
  - with_trust() floor at 0.0 for score, lowercase tier
  - has_collaborated() with and without specific address
  - on_platform() / exclude() / limit()
  - limit() clamps to [1, 100]
  - Multiple filters are AND-combined in to_params()
  - to_params() omits keys with default/falsy values
  - CapabilityStats: all fields populated from dict
  - CapabilityProfile: by_action_type and by_tag populated as CapabilityStats
  - CapabilityProfile.has_evidenced() checks both dimensions
  - CapabilityProfile.evidence_count() returns correct value
  - CapabilityProfile.top_capabilities() sorts by specified metric
  - CapabilityProfile with empty data: graceful defaults
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from jito_agent.discovery import CapabilityProfile, CapabilityStats, DiscoveryQuery


# ---------------------------------------------------------------------------
# DiscoveryQuery — unit tests
# ---------------------------------------------------------------------------

class TestDiscoveryQueryDefaults(unittest.TestCase):
    """Default state of a freshly created DiscoveryQuery."""

    def test_default_to_params_has_limit(self):
        q = DiscoveryQuery()
        params = q.to_params()
        self.assertIn("limit", params)
        self.assertEqual(params["limit"], "20")

    def test_default_to_params_minimal(self):
        """Default query emits only limit — no other filters."""
        q = DiscoveryQuery()
        params = q.to_params()
        self.assertEqual(set(params.keys()), {"limit"})

    def test_describe_empty_query(self):
        q = DiscoveryQuery()
        desc = q.describe()
        self.assertIn("DiscoveryQuery", desc)
        self.assertIn("all", desc)


class TestDiscoveryQueryWithCapability(unittest.TestCase):

    def test_capability_emitted_in_params(self):
        q = DiscoveryQuery().with_capability("security")
        params = q.to_params()
        self.assertEqual(params["capability"], "security")
        self.assertIn("min_log_count", params)

    def test_capability_lowercased(self):
        q = DiscoveryQuery().with_capability("Security-Audit")
        params = q.to_params()
        self.assertEqual(params["capability"], "security-audit")

    def test_capability_stripped(self):
        q = DiscoveryQuery().with_capability("  data-analysis  ")
        params = q.to_params()
        self.assertEqual(params["capability"], "data-analysis")

    def test_min_logs_respected(self):
        q = DiscoveryQuery().with_capability("security", min_logs=20)
        params = q.to_params()
        self.assertEqual(params["min_log_count"], "20")

    def test_min_logs_clamped_to_1(self):
        q = DiscoveryQuery().with_capability("security", min_logs=0)
        params = q.to_params()
        self.assertEqual(params["min_log_count"], "1")

    def test_min_logs_negative_clamped_to_1(self):
        q = DiscoveryQuery().with_capability("security", min_logs=-5)
        params = q.to_params()
        self.assertEqual(params["min_log_count"], "1")

    def test_min_evidenced_omitted_when_zero(self):
        q = DiscoveryQuery().with_capability("security", min_evidenced=0)
        params = q.to_params()
        self.assertNotIn("min_evidence_count", params)

    def test_min_evidenced_included_when_positive(self):
        q = DiscoveryQuery().with_capability("security", min_evidenced=15)
        params = q.to_params()
        self.assertEqual(params["min_evidence_count"], "15")

    def test_min_evidenced_negative_clamped_to_zero(self):
        q = DiscoveryQuery().with_capability("security", min_evidenced=-3)
        params = q.to_params()
        self.assertNotIn("min_evidence_count", params)

    def test_describe_includes_capability(self):
        q = DiscoveryQuery().with_capability("security", min_logs=20, min_evidenced=10)
        desc = q.describe()
        self.assertIn("security", desc)
        self.assertIn("min_logs=20", desc)
        self.assertIn("min_evidenced=10", desc)


class TestDiscoveryQueryWithTrust(unittest.TestCase):

    def test_min_score_included_when_positive(self):
        q = DiscoveryQuery().with_trust(min_score=15.0)
        params = q.to_params()
        self.assertEqual(params["min_score"], "15.0")

    def test_min_score_omitted_when_zero(self):
        q = DiscoveryQuery().with_trust(min_score=0.0)
        params = q.to_params()
        self.assertNotIn("min_score", params)

    def test_min_tier_included(self):
        q = DiscoveryQuery().with_trust(min_tier="attested")
        params = q.to_params()
        self.assertEqual(params["min_tier"], "attested")

    def test_min_tier_lowercased(self):
        q = DiscoveryQuery().with_trust(min_tier="ATTESTED")
        params = q.to_params()
        self.assertEqual(params["min_tier"], "attested")

    def test_min_tier_stripped(self):
        q = DiscoveryQuery().with_trust(min_tier="  stake-backed  ")
        params = q.to_params()
        self.assertEqual(params["min_tier"], "stake-backed")

    def test_min_tier_omitted_when_empty(self):
        q = DiscoveryQuery().with_trust(min_tier="")
        params = q.to_params()
        self.assertNotIn("min_tier", params)

    def test_describe_includes_trust_params(self):
        q = DiscoveryQuery().with_trust(min_score=10.0, min_tier="attested")
        desc = q.describe()
        self.assertIn("attested", desc)
        self.assertIn("10.0", desc)


class TestDiscoveryQueryHasCollaborated(unittest.TestCase):

    def test_has_collaborated_flag_set(self):
        q = DiscoveryQuery().has_collaborated()
        params = q.to_params()
        self.assertEqual(params["has_collaborated"], "true")

    def test_has_collaborated_omitted_by_default(self):
        q = DiscoveryQuery()
        params = q.to_params()
        self.assertNotIn("has_collaborated", params)

    def test_collaborated_with_specific_address(self):
        q = DiscoveryQuery().has_collaborated(with_address="0xabc123")
        params = q.to_params()
        self.assertEqual(params["collaborated_with"], "0xabc123")
        self.assertEqual(params["has_collaborated"], "true")

    def test_collaborated_with_stripped(self):
        q = DiscoveryQuery().has_collaborated(with_address="  0xabc  ")
        params = q.to_params()
        self.assertEqual(params["collaborated_with"], "0xabc")

    def test_collaborated_with_empty_omits_collaborated_with_key(self):
        q = DiscoveryQuery().has_collaborated(with_address="")
        params = q.to_params()
        self.assertNotIn("collaborated_with", params)

    def test_describe_shows_collaborated_with(self):
        q = DiscoveryQuery().has_collaborated(with_address="0xabc...")
        desc = q.describe()
        self.assertIn("0xabc...", desc)

    def test_describe_shows_has_collaborated_without_address(self):
        q = DiscoveryQuery().has_collaborated()
        desc = q.describe()
        self.assertIn("has_collaborated=true", desc)


class TestDiscoveryQueryMiscFilters(unittest.TestCase):

    def test_on_platform(self):
        q = DiscoveryQuery().on_platform("langchain")
        params = q.to_params()
        self.assertEqual(params["platform"], "langchain")

    def test_on_platform_lowercased_stripped(self):
        q = DiscoveryQuery().on_platform("  LangChain  ")
        params = q.to_params()
        self.assertEqual(params["platform"], "langchain")

    def test_on_platform_omitted_when_empty(self):
        q = DiscoveryQuery()
        params = q.to_params()
        self.assertNotIn("platform", params)

    def test_exclude_single_address(self):
        q = DiscoveryQuery().exclude("0xbad1")
        params = q.to_params()
        self.assertEqual(params["exclude"], "0xbad1")

    def test_exclude_multiple_addresses(self):
        q = DiscoveryQuery().exclude("0xbad1", "0xbad2", "0xbad3")
        params = q.to_params()
        excluded = params["exclude"].split(",")
        self.assertIn("0xbad1", excluded)
        self.assertIn("0xbad2", excluded)
        self.assertIn("0xbad3", excluded)

    def test_exclude_chained(self):
        q = DiscoveryQuery().exclude("0xa").exclude("0xb")
        params = q.to_params()
        excluded = params["exclude"].split(",")
        self.assertIn("0xa", excluded)
        self.assertIn("0xb", excluded)

    def test_exclude_omitted_when_empty(self):
        q = DiscoveryQuery()
        params = q.to_params()
        self.assertNotIn("exclude", params)

    def test_with_tags_included(self):
        q = DiscoveryQuery().with_tags("security", "defi")
        params = q.to_params()
        self.assertIn("tags", params)
        tags = params["tags"].split(",")
        self.assertIn("security", tags)
        self.assertIn("defi", tags)

    def test_with_tags_lowercased_stripped(self):
        q = DiscoveryQuery().with_tags("  Security  ", "DeFi")
        params = q.to_params()
        tags = params["tags"].split(",")
        self.assertIn("security", tags)
        self.assertIn("defi", tags)

    def test_with_tags_omits_empty_strings(self):
        q = DiscoveryQuery().with_tags("security", "", "  ")
        params = q.to_params()
        tags = params["tags"].split(",")
        self.assertNotIn("", tags)


class TestDiscoveryQueryLimit(unittest.TestCase):

    def test_custom_limit(self):
        q = DiscoveryQuery().limit(5)
        params = q.to_params()
        self.assertEqual(params["limit"], "5")

    def test_limit_clamped_to_1_minimum(self):
        q = DiscoveryQuery().limit(0)
        params = q.to_params()
        self.assertEqual(params["limit"], "1")

    def test_limit_negative_clamped_to_1(self):
        q = DiscoveryQuery().limit(-50)
        params = q.to_params()
        self.assertEqual(params["limit"], "1")

    def test_limit_clamped_to_100_maximum(self):
        q = DiscoveryQuery().limit(500)
        params = q.to_params()
        self.assertEqual(params["limit"], "100")

    def test_limit_exactly_100_accepted(self):
        q = DiscoveryQuery().limit(100)
        params = q.to_params()
        self.assertEqual(params["limit"], "100")


class TestDiscoveryQueryComposed(unittest.TestCase):
    """Multiple filters applied together."""

    def test_full_query_params(self):
        q = (
            DiscoveryQuery()
            .with_capability("security", min_logs=20, min_evidenced=15)
            .with_trust(min_score=10.0, min_tier="attested")
            .has_collaborated(with_address="0xpeer")
            .on_platform("langchain")
            .exclude("0xbad")
            .limit(5)
        )
        params = q.to_params()
        self.assertEqual(params["capability"], "security")
        self.assertEqual(params["min_log_count"], "20")
        self.assertEqual(params["min_evidence_count"], "15")
        self.assertEqual(params["min_score"], "10.0")
        self.assertEqual(params["min_tier"], "attested")
        self.assertEqual(params["has_collaborated"], "true")
        self.assertEqual(params["collaborated_with"], "0xpeer")
        self.assertEqual(params["platform"], "langchain")
        self.assertEqual(params["exclude"], "0xbad")
        self.assertEqual(params["limit"], "5")

    def test_full_query_describe(self):
        q = (
            DiscoveryQuery()
            .with_capability("security", min_logs=20)
            .with_trust(min_tier="attested")
            .has_collaborated()
        )
        desc = q.describe()
        self.assertIn("security", desc)
        self.assertIn("attested", desc)
        self.assertIn("has_collaborated", desc)

    def test_fluent_builder_returns_same_instance(self):
        """Each builder method returns the same DiscoveryQuery object."""
        q = DiscoveryQuery()
        q2 = q.with_capability("security")
        self.assertIs(q, q2)

        q3 = q.with_trust(min_score=5.0)
        self.assertIs(q, q3)

        q4 = q.has_collaborated()
        self.assertIs(q, q4)


# ---------------------------------------------------------------------------
# CapabilityStats
# ---------------------------------------------------------------------------

class TestCapabilityStats(unittest.TestCase):

    def test_all_fields_from_dict(self):
        data = {
            "total_logs": 42,
            "evidenced_logs": 35,
            "attested_logs": 20,
            "success_rate": 0.95,
            "evidence_rate": 0.833,
            "last_active": 1712000000.0,
        }
        stats = CapabilityStats(data)
        self.assertEqual(stats.total_logs, 42)
        self.assertEqual(stats.evidenced_logs, 35)
        self.assertEqual(stats.attested_logs, 20)
        self.assertAlmostEqual(stats.success_rate, 0.95)
        self.assertAlmostEqual(stats.evidence_rate, 0.833)
        self.assertEqual(stats.last_active, 1712000000.0)

    def test_defaults_when_empty_dict(self):
        stats = CapabilityStats({})
        self.assertEqual(stats.total_logs, 0)
        self.assertEqual(stats.evidenced_logs, 0)
        self.assertEqual(stats.attested_logs, 0)
        self.assertEqual(stats.success_rate, 0.0)
        self.assertEqual(stats.evidence_rate, 0.0)
        self.assertEqual(stats.last_active, 0.0)

    def test_repr_contains_key_info(self):
        stats = CapabilityStats({"total_logs": 10, "evidenced_logs": 8,
                                  "attested_logs": 5, "success_rate": 0.9})
        r = repr(stats)
        self.assertIn("10", r)
        self.assertIn("8", r)


# ---------------------------------------------------------------------------
# CapabilityProfile
# ---------------------------------------------------------------------------

class TestCapabilityProfile(unittest.TestCase):

    def _make_profile(self):
        data = {
            "address": "0xagent1234567890abcdef",
            "by_action_type": {
                "session_complete": {
                    "total_logs": 100,
                    "evidenced_logs": 80,
                    "attested_logs": 50,
                    "success_rate": 0.92,
                    "evidence_rate": 0.80,
                    "last_active": 1712000000.0,
                },
                "security_audit": {
                    "total_logs": 25,
                    "evidenced_logs": 25,
                    "attested_logs": 10,
                    "success_rate": 0.88,
                    "evidence_rate": 1.0,
                    "last_active": 1711900000.0,
                },
            },
            "by_tag": {
                "security": {
                    "total_logs": 30,
                    "evidenced_logs": 28,
                    "attested_logs": 12,
                    "success_rate": 0.87,
                    "evidence_rate": 0.93,
                    "last_active": 1711850000.0,
                },
                "data-analysis": {
                    "total_logs": 15,
                    "evidenced_logs": 5,
                    "attested_logs": 2,
                    "success_rate": 0.80,
                    "evidence_rate": 0.33,
                    "last_active": 1711800000.0,
                },
            },
            "collab_partners": ["0xpartnerA", "0xpartnerB", "0xpartnerC"],
        }
        return CapabilityProfile(data)

    def test_address_stored(self):
        profile = self._make_profile()
        self.assertEqual(profile.address, "0xagent1234567890abcdef")

    def test_by_action_type_populated(self):
        profile = self._make_profile()
        self.assertIn("session_complete", profile.by_action_type)
        self.assertIn("security_audit", profile.by_action_type)
        self.assertIsInstance(profile.by_action_type["session_complete"], CapabilityStats)

    def test_by_tag_populated(self):
        profile = self._make_profile()
        self.assertIn("security", profile.by_tag)
        self.assertIn("data-analysis", profile.by_tag)
        self.assertIsInstance(profile.by_tag["security"], CapabilityStats)

    def test_collab_partners_stored(self):
        profile = self._make_profile()
        self.assertEqual(len(profile.collab_partners), 3)
        self.assertIn("0xpartnerA", profile.collab_partners)

    def test_has_evidenced_by_action_type(self):
        profile = self._make_profile()
        # security_audit has 25 evidenced logs
        self.assertTrue(profile.has_evidenced("security_audit", min_count=25))
        self.assertFalse(profile.has_evidenced("security_audit", min_count=26))

    def test_has_evidenced_by_tag(self):
        profile = self._make_profile()
        # security tag has 28 evidenced logs
        self.assertTrue(profile.has_evidenced("security", min_count=28))
        self.assertFalse(profile.has_evidenced("security", min_count=29))

    def test_has_evidenced_case_insensitive(self):
        profile = self._make_profile()
        self.assertTrue(profile.has_evidenced("SECURITY", min_count=1))
        self.assertTrue(profile.has_evidenced("Security_Audit", min_count=1))

    def test_has_evidenced_unknown_capability(self):
        profile = self._make_profile()
        self.assertFalse(profile.has_evidenced("nonexistent_capability", min_count=1))

    def test_evidence_count_from_action_type(self):
        profile = self._make_profile()
        self.assertEqual(profile.evidence_count("security_audit"), 25)

    def test_evidence_count_from_tag(self):
        profile = self._make_profile()
        self.assertEqual(profile.evidence_count("security"), 28)

    def test_evidence_count_unknown_returns_zero(self):
        profile = self._make_profile()
        self.assertEqual(profile.evidence_count("does_not_exist"), 0)

    def test_top_capabilities_by_total_logs(self):
        profile = self._make_profile()
        top = profile.top_capabilities(n=2, by="total_logs")
        # session_complete has 100, security has 30 (from by_tag)
        self.assertEqual(top[0], "session_complete")
        self.assertIn(top[1], ("security", "security_audit"))

    def test_top_capabilities_by_evidenced_logs(self):
        profile = self._make_profile()
        top = profile.top_capabilities(n=1, by="evidenced_logs")
        # session_complete has 80 evidenced — highest
        self.assertEqual(top[0], "session_complete")

    def test_top_capabilities_limit_respected(self):
        profile = self._make_profile()
        top = profile.top_capabilities(n=2)
        self.assertEqual(len(top), 2)

    def test_top_capabilities_n_exceeds_count(self):
        profile = self._make_profile()
        # 4 total capabilities — asking for 10 returns all 4
        top = profile.top_capabilities(n=10)
        self.assertEqual(len(top), 4)

    def test_repr_contains_address_prefix(self):
        profile = self._make_profile()
        r = repr(profile)
        self.assertIn("0xagent1234", r)

    def test_repr_contains_collab_count(self):
        profile = self._make_profile()
        r = repr(profile)
        self.assertIn("3", r)


class TestCapabilityProfileEmpty(unittest.TestCase):
    """CapabilityProfile handles missing/empty data gracefully."""

    def test_empty_profile_no_crash(self):
        profile = CapabilityProfile({})
        self.assertEqual(profile.address, "")
        self.assertEqual(profile.by_action_type, {})
        self.assertEqual(profile.by_tag, {})
        self.assertEqual(profile.collab_partners, [])

    def test_has_evidenced_returns_false_on_empty(self):
        profile = CapabilityProfile({})
        self.assertFalse(profile.has_evidenced("security"))

    def test_evidence_count_returns_zero_on_empty(self):
        profile = CapabilityProfile({})
        self.assertEqual(profile.evidence_count("security"), 0)

    def test_top_capabilities_returns_empty_on_empty(self):
        profile = CapabilityProfile({})
        top = profile.top_capabilities(n=5)
        self.assertEqual(top, [])


if __name__ == "__main__":
    unittest.main()
