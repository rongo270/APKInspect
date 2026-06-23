"""Scoring engine: bounds, ordering, grades."""
import unittest

from apkinspect.model import Finding
from apkinspect.scoring import compute_score, grade_for


def f(sev, cat="config", i=0):
    return Finding(id=f"X{i}", title="t", severity=sev, category=cat)


class TestScoring(unittest.TestCase):
    def test_empty_is_perfect(self):
        score, grade, label = compute_score([])
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")

    def test_bounds(self):
        many = [f("CRITICAL", cat=c, i=n) for n in range(20) for c in ("a", "b", "c")]
        score, _, _ = compute_score(many)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_severity_ordering(self):
        crit = compute_score([f("CRITICAL")])[0]
        high = compute_score([f("HIGH")])[0]
        med = compute_score([f("MEDIUM")])[0]
        low = compute_score([f("LOW")])[0]
        info = compute_score([f("INFO")])[0]
        self.assertLess(crit, high)
        self.assertLess(high, med)
        self.assertLess(med, low)
        self.assertLess(low, info)
        self.assertEqual(info, 100)

    def test_single_low_barely_moves(self):
        self.assertGreaterEqual(compute_score([f("LOW")])[0], 95)

    def test_critical_is_serious(self):
        self.assertLessEqual(compute_score([f("CRITICAL")])[0], 60)

    def test_more_findings_never_increase_score(self):
        base = compute_score([f("MEDIUM", i=0)])[0]
        more = compute_score([f("MEDIUM", i=0), f("MEDIUM", cat="net", i=1)])[0]
        self.assertLessEqual(more, base)

    def test_diminishing_returns_same_category(self):
        # 10 LOW perms shouldn't tank the score below a single MEDIUM
        perms = [f("LOW", cat="permission", i=n) for n in range(10)]
        self.assertGreater(compute_score(perms)[0], 75)

    def test_grade_thresholds(self):
        self.assertEqual(grade_for(95)[0], "A")
        self.assertEqual(grade_for(80)[0], "B")
        self.assertEqual(grade_for(65)[0], "C")
        self.assertEqual(grade_for(45)[0], "D")
        self.assertEqual(grade_for(10)[0], "F")


if __name__ == "__main__":
    unittest.main()
