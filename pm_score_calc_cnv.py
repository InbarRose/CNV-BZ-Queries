#!/usr/bin/env python

import ssl
import argparse
import os
import datetime
import logging
import collections

# import bugzilla
from bugzilla.rhbugzilla import RHBugzilla

logger = logging.getLogger('bz_pm_score_updater')

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

TimeMinMax = collections.namedtuple('TimeMinMax', 'min max')

# Constants
URL = "bugzilla.redhat.com"
NO_TICKETS_KW = "NoActiveCustomerTickets"
REDHAT_COM_SUPPORT_CASES = 'https://access.redhat.com/support/cases'
PRODUCT_NAME = 'Container Native Virtualization (CNV)'
VALID_BUG_STATUS_LIST = [
    'NEW',
    'ASSIGNED',
    'POST',
    'MODIFIED',
    'ON_QA',
    'VERIFIED'
]
INCLUDE_FIELDS = [
    '_default',
    '_custom',
    'flags',
    'external_bugs'
]
VALID_TIME_TYPES = ['hours', 'days']
VALID_HOURS = TimeMinMax(1, 23)
VALID_DAYS = TimeMinMax(1, 30)

# Scores
REGRESSION = 600
BLOCKER = 1500
AUTOMATION_BLOCKER = 1100
CUSTOMER_TICKET_OPEN = 400
CUSTOMER_TICKET_CLOSED = 100
CEEBumpPMScore = 1500
CIR_FLAG = 500
SEVERITY_SCORE = {
    'urgent': 2970,
    'high': 660,
    'medium': 330,
    'low': 10,
    'unspecified': 0
}
PRIORITY_SCORE = {
    'urgent': 2700,
    'high': 600,
    'medium': 300,
    'low': 10,
    'unspecified': 0
}


class EnvDefault(argparse.Action):
    """allows using environment variables instead of passing arguments directly"""

    def __init__(self, env_var, required=True, default=None, **kwargs):
        if not default and env_var:
            if env_var in os.environ:
                default = os.environ[env_var]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required,
                                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


class BZBugScoreUpdater(object):
    """class for orchestrating the PM score updates on bugs"""

    def __init__(self, bz_api) -> None:
        super().__init__()
        self.bz_api = bz_api

    def get_bz_bug_scorer(self, bz_id):
        bug = self.bz_api.getbug(bz_id, include_fields=INCLUDE_FIELDS)
        return BZBugScorer(bug, self.bz_api)

    def query_bugs(self, query):
        bugs = self.bz_api.query(query)
        return bugs

    @staticmethod
    def make_query(last_change_time=None):
        query = {
            'bug_status': VALID_BUG_STATUS_LIST,
            'product': PRODUCT_NAME,
            'include_fields': INCLUDE_FIELDS
        }
        if last_change_time:
            query['last_change_time'] = last_change_time
        return query

    def perform_bug_score_updates(self, last_change_time=None):
        bugs = self._fetch_bugs(last_change_time)
        self._update_bug_scores(bugs)

    def _fetch_bugs(self, last_change_time):
        query = self.make_query(last_change_time)
        logger.info(f"Querying BugZilla: {query}")
        bugs = self.query_bugs(query)
        return bugs

    def _update_bug_scores(self, bugs):
        logger.info(f"Number of BZ Bugs found in query: {len(bugs)}")
        logger.info("Index: Score( before => after ) BZ_URL [<updated-status>]")
        for idx, bug in enumerate(bugs):
            bz_bs = self.get_bz_bug_scorer(bug.id)
            updated = bz_bs.update()  # implies bz_bs.calc_score()
            logger.info(f"{idx:03}:\t( {bz_bs.old_score} => {bz_bs.new_score} ) {bz_bs.bug_url} [{updated}]")


class BZBugScorer(object):
    """class which calculates and updates the PM score"""

    def __init__(self, bug, bz_api, debug_mode=False):
        self.score = None
        self.bug = bug
        self.bz_api = bz_api
        self.debug_mode = debug_mode

    @property
    def bug_url(self):
        return f"https://{URL}/show_bug.cgi?id={self.bug.id}"

    @property
    def log_id(self):
        return self.bug.id

    @property
    def old_score(self):
        return int(self.bug.cf_pm_score)

    @property
    def new_score(self):
        return int(self.score)

    @property
    def needs_update(self):
        return bool(self.old_score != self.new_score)

    def calculation_msg(self, msg):
        self.debug_msg(f"{msg}")

    def debug_msg(self, msg):
        if self.debug_mode:
            logger.debug(f"{self.log_id}: {msg}")

    def info_msg(self, msg):
        logger.info(f"{self.log_id}: {msg}")

    def calc_regression(self):
        score = 0
        if 'Regression' in self.bug.keywords:
            score = REGRESSION
        if score:
            self.calculation_msg(f"Regression keyword: {score}")
        return score

    def calc_blocker(self):
        score = 0
        if self.bug.get_flag_status('blocker') is not None:
            score = BLOCKER
        if score:
            self.calculation_msg(f"Blocker: {score}")
        return score

    def calc_automation_blocker(self):
        score = 0
        if 'AutomationBlocker' in self.bug.keywords:
            score = AUTOMATION_BLOCKER
        if score:
            self.calculation_msg(f"Automation Blocker: {score}")
        return score

    def calc_cee(self):
        score = 0
        self.debug_msg(f'INTERNAL: {self.bug.cf_internal_whiteboard}')
        if 'CEEBumpPMScore' in self.bug.cf_internal_whiteboard:
            score = CEEBumpPMScore
        if score:
            self.calculation_msg(f"CEEBumpPMScore internal whiteboard: {score}")
        return score

    def calc_cir_flag(self):
        score = 0
        if self.bug.get_flag_status('cee_cir') == '+':
            score = CIR_FLAG
        if score:
            self.calculation_msg(f"cee_cir+ flag: {score}")
        return score

    def calc_severity(self):
        score = SEVERITY_SCORE[self.bug.severity]
        if self.bug.severity != "unspecified":
            self.calculation_msg(f"Severity score: {score}")
        return score

    def calc_priority(self):
        score = PRIORITY_SCORE[self.bug.priority]
        if self.bug.priority != "unspecified":
            self.calculation_msg(f"Priority score: {score}")
        return score

    @staticmethod
    def item_is_support_case(item):
        return bool(REDHAT_COM_SUPPORT_CASES in item['type']['full_url'])

    def calc_tickets(self):
        """
        iterate over external bugs to find customer support case tickets
        calculate score based on how many open or closed tickets we find

        also will update the bug with a NoActiveCustomerTickets flag
        on the bugs Internal Whiteboard to reflect the status tickets
        """
        ticket_totals, ticket_count, ticket_open = 0, 0, 0

        for item in filter(self.item_is_support_case, self.bug.external_bugs):
            if item['ext_status'] == "Closed":
                ticket_count += 1
                ticket_totals += CUSTOMER_TICKET_CLOSED
            elif "Waiting" in item['ext_status']:
                ticket_open += 1
                ticket_count += 1
                ticket_totals += CUSTOMER_TICKET_OPEN

                if NO_TICKETS_KW in self.bug.cf_internal_whiteboard:
                    self.remove_no_customer_ticket_flag()

        if ticket_open == 0 and ticket_count != 0:
            if NO_TICKETS_KW not in self.bug.cf_internal_whiteboard:
                self.add_no_customer_ticket_flag()

        score = ticket_count * ticket_totals
        if score:
            self.calculation_msg(f"Tickets: {score}")
        return score

    def add_no_customer_ticket_flag(self):
        if self.bug.cf_internal_whiteboard.strip() == "":
            self.bug.cf_internal_whiteboard = NO_TICKETS_KW
        else:
            self.bug.cf_internal_whiteboard = f"{self.bug.cf_internal_whiteboard}, {NO_TICKETS_KW}"
        self.bz_api.update_bugs(self.bug.id, {'cf_internal_whiteboard': self.bug.cf_internal_whiteboard, 'nomail': 1})
        self.debug_msg("NoCustomerTickets flag added")

    def remove_no_customer_ticket_flag(self):
        new_text = self.bug.cf_internal_whiteboar.replace(f", {NO_TICKETS_KW}", "").replace(NO_TICKETS_KW, "")
        self.bug.cf_internal_whiteboard = new_text
        self.bz_api.update_bugs(self.bug.id, {'cf_internal_whiteboard': self.bug.cf_internal_whiteboard, 'nomail': 1})
        self.debug_msg("NoCustomerTickets flag removed")

    def calc_score(self):
        """run all calculations and provide final score"""
        score = [
            self.calc_regression(),
            self.calc_blocker(),
            self.calc_severity(),
            self.calc_priority(),
            self.calc_tickets(),
            self.calc_automation_blocker(),
            self.calc_cee(),
            self.calc_cir_flag()
        ]
        self.score = sum(score)
        return self.score

    def _update(self):
        self.bz_api.update_bugs(self.bug.id, {'cf_pm_score': self.score, 'nomail': 1})

    def update(self):
        """
        perform score calculation and then update bug with new score if it is different than old score
        returns True if score was updated, otherwise false.
        """
        if not self.score:
            self.calc_score()  # do not calculate again if we already have the score
        if self.needs_update:
            self._update()
            return True
        else:
            return False


def utc_format(dt, timespec='milliseconds'):
    """convert datetime to string in UTC format (YYYY-mm-ddTHH:MM:SS.mmmZ)"""
    iso_str = dt.astimezone(datetime.timezone.utc).isoformat('T', timespec)
    return iso_str.replace('+00:00', 'Z')


def get_utc_time_ago(time_type, time_value):
    """
    convert time delta into UTC formatted string representing a time in the past according to the specified delta
    """
    assert time_type in VALID_TIME_TYPES
    if time_type == "hours":
        delta = datetime.datetime.now() - datetime.timedelta(hours=time_value)
    else:  # days
        delta = datetime.datetime.now() - datetime.timedelta(days=time_value)
    last_change_time = utc_format(delta, timespec='seconds')
    return last_change_time


def parse_arguments():
    parser = argparse.ArgumentParser(description=f'{__file__} command line arguments')
    parser.add_argument('-k', '--key', required=True, type=str, action=EnvDefault,
                        env_var='BZ_API_KEY',
                        help='The Bugzilla API key')
    parser.add_argument('-p', '--time_delta_param', required=False, type=str, action=EnvDefault,
                        env_var='TIME_DELTA_PARAM',
                        help=f'The time delta parameter: {VALID_TIME_TYPES}')
    parser.add_argument('-v', '--time_delta_value', required=False, type=int, action=EnvDefault,
                        env_var='TIME_DELTA_VALUE',
                        help=f'The time delta value: number of {VALID_TIME_TYPES}. '
                             f'For hours use {VALID_HOURS.min} to {VALID_HOURS.max}, '
                             f'For days use {VALID_DAYS.min} to {VALID_DAYS.max}.')
    args = parser.parse_args()

    if args.time_delta_param is not None and args.time_delta_param not in VALID_TIME_TYPES:
        parser.error(f"Invalid time_delta_param. Valid values include: {VALID_TIME_TYPES}")

    if args.time_delta_param is not None and args.time_delta_value is None:
        parser.error("The time_delta_value must be specified")

    if args.time_delta_param == "hours" and not VALID_HOURS.min <= args.time_delta_value <= VALID_HOURS.max:
        parser.error(f"For hours use values from {VALID_HOURS.min} to {VALID_HOURS.max}")

    if args.time_delta_param == "days" and not VALID_DAYS.min <= args.time_delta_value <= VALID_DAYS.max:
        parser.error(f"For days use values from {VALID_DAYS.min} to {VALID_DAYS.max}")

    if args.time_delta_param is not None and args.time_delta_value is not None:
        last_change_time = get_utc_time_ago(args.time_delta_param, args.time_delta_value)
    else:
        last_change_time = None

    return args.key, last_change_time


def main(key, last_change_time=None):
    logger.info(f"Starting process: last_change_time={last_change_time}")
    bz_api = RHBugzilla(url=URL, api_key=key)
    bz_bsu = BZBugScoreUpdater(bz_api)
    bz_bsu.perform_bug_score_updates(last_change_time)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        main(*parse_arguments())
    except Exception as exc:
        logger.exception(f"exception in main... {exc}", exc_info=True)
