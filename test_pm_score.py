import unittest
import os
from .pm_score_calc_cnv import RHBugzilla, BZBugScoreUpdater, BZBugScorer, URL, INCLUDE_FIELDS

test_key = os.getenv('BZ_API_KEY')
test_bug_id = os.getenv('BZ_TEST_ID')
test_bug_score = os.getenv('BZ_TEST_SCORE')


class ScoreTester(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        assert test_key

    def test_get_bug_score(self):
        self.assertIsNotNone(test_bug_id)
        self.assertIsNotNone(test_bug_score)
        bz_api = RHBugzilla(url=URL, api_key=test_key)
        bz_bsu = BZBugScoreUpdater(bz_api)
        bz_bs = bz_bsu.get_bz_bug_scorer(test_bug_id)
        score = bz_bs.calc_score()
        self.assertIsNotNone(score)
        expected_score = int(test_bug_score)
        self.assertEqual(expected_score, score)

    def test_bz_url(self):
        self.assertIsNotNone(test_bug_id)
        bz_api = RHBugzilla(url=URL, api_key=test_key)
        bz_bsu = BZBugScoreUpdater(bz_api)
        bz_bs = bz_bsu.get_bz_bug_scorer(test_bug_id)
        self.assertEqual(f"https://{URL}/show_bug.cgi?id={test_bug_id}", bz_bs.bug_url)

    def test_mock_update_with_logging(self):
        self.assertIsNotNone(test_bug_id)

        with self.assertLogs('bz_pm_score_updater', level='INFO') as cm:
            bz_api = RHBugzilla(url=URL, api_key=test_key)
            bz_bsu = BZBugScoreUpdater(bz_api)
            BZBugScorer._update = lambda: None  # mock the update process to do nothing
            bug = bz_api.getbug(test_bug_id, include_fields=INCLUDE_FIELDS)
            bz_bsu._update_bug_scores([bug])

        self.assertEqual(
            cm.output,
            [
                'INFO:bz_pm_score_updater:Number of BZ Bugs found in query: 1',
                'INFO:bz_pm_score_updater:Index: Score( before => after ) BZ_URL [<updated-status>]',
                f'INFO:bz_pm_score_updater:000:\t'
                f'( {test_bug_score} => {test_bug_score} ) https://{URL}/show_bug.cgi?id={test_bug_id} [False]'
            ])


if __name__ == '__main__':
    unittest.main()
