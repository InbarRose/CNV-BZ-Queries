import unittest
import os
from pm_score_calc_cnv import RHBugzilla, BZBugScoreUpdater, URL

test_key = os.getenv('BZ_API_KEY')
test_bug_id = os.getenv('BZ_TEST_ID')
test_bug_score = os.getenv('BZ_TEST_SCORE')


class ScoreTester(unittest.TestCase):

    def test_get_bug_score(self):
        self.assertIsNotNone(test_key)
        self.assertIsNotNone(test_bug_id)
        self.assertIsNotNone(test_bug_score)
        expected_score = int(test_bug_score)
        bz_api = RHBugzilla(url=URL, api_key=test_key)
        bz_bsu = BZBugScoreUpdater(bz_api)
        bz_bs = bz_bsu.get_bz_bug_scorer(test_bug_id)
        score = bz_bs.calc_score()
        self.assertIsNotNone(score)
        self.assertEquals(expected_score, score)


if __name__ == '__main__':
    unittest.main()
