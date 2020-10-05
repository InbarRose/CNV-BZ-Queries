#!/usr/bin/env python
from __future__ import division, print_function

import ssl
import argparse
import os
import datetime

# import bugzilla
from bugzilla.rhbugzilla import RHBugzilla

INCLUDE_FIELDS = ['_default', '_custom', 'flags', 'external_bugs']

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Constants
URL = "bugzilla.redhat.com"
NO_TICKETS_KW = "NoActiveCustomerTickets"
PRODUCT_NAME = 'Container Native Virtualization (CNV)'
VALID_BUG_STATUS_LIST = [
    'NEW',
    'ASSIGNED',
    'POST',
    'MODIFIED',
    'ON_QA',
    'VERIFIED'
]

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
        query = self.make_query(last_change_time)
        bugs = self.query_bugs(query)
        print(f"Number of BZ Bugs to update: {len(bugs)}")
        print("Index, Bug ID, before, after")
        for idx, bug in enumerate(bugs):
            bz_bs = self.get_bz_bug_scorer(bug.id)
            bz_bs.calc_score()
            print(f"{idx}, {bug.id}, {bug.cf_pm_score}, {bz_bs.score}")
            bz_bs.update()


class BZBugScorer(object):
    """class which calculates and updates the PM score"""

    def __init__(self, bug, bz_api, debug_mode=False):
        self.score = None
        self.bug = bug
        self.bz_api = bz_api
        self.debug_mode = debug_mode

    def debug_msg(self, msg):
        if self.debug_mode:
            print(msg)

    def calc_regression(self):
        score = 0
        if 'Regression' in self.bug.keywords:
            score = REGRESSION
        if score:
            self.debug_msg(f"Calculation debugs: Regression keyword: {score}")
        return score

    def calc_blocker(self):
        score = 0
        if self.bug.get_flag_status('blocker') is not None:
            score = BLOCKER
        if score:
            self.debug_msg("Calculation debugs: Blocker: {}".format(score))
        return score

    def calc_automation_blocker(self):
        score = 0
        if 'AutomationBlocker' in self.bug.keywords:
            score = AUTOMATION_BLOCKER
        if score:
            self.debug_msg(f"Calculation debugs: Automation Blocker: {score}")
        return score

    def calc_cee(self):
        score = 0
        self.debug_msg('INTERNAL: %s' % self.bug.cf_internal_whiteboard)
        if 'CEEBumpPMScore' in self.bug.cf_internal_whiteboard:
            score = CEEBumpPMScore
        if score:
            self.debug_msg(f"Calculation debugs: CEEBumpPMScore internal whiteboard: {score}")
        return score

    def calc_cir_flag(self):
        score = 0
        if self.bug.get_flag_status('cee_cir') == '+':
            score = CIR_FLAG
        if score:
            self.debug_msg("Calculation debugs: cee_cir+ flag: {}".format(score))
        return score

    def calc_severity(self):
        if self.bug.severity != "unspecified":
            self.debug_msg(f"Calculation debugs: Severity score: {SEVERITY_SCORE[self.bug.severity]}")
        return SEVERITY_SCORE[self.bug.severity]

    def calc_priority(self):
        if self.bug.priority != "unspecified":
            self.debug_msg(f"Calculation debugs: Priority score: {PRIORITY_SCORE[self.bug.priority]}")
        return PRIORITY_SCORE[self.bug.priority]

    def calc_tickets(self):
        ticket_totals = 0
        ticket_count = 0
        ticket_open = 0
        for item in self.bug.external_bugs:
            if 'https://access.redhat.com/support/cases' in item['type']['full_url']:
                if item['ext_status'] == "Closed":
                    ticket_count += 1
                    ticket_totals += CUSTOMER_TICKET_CLOSED
                elif "Waiting" in item['ext_status']:
                    ticket_open += 1
                    ticket_count += 1
                    ticket_totals += CUSTOMER_TICKET_OPEN
                    if NO_TICKETS_KW in self.bug.cf_internal_whiteboard:
                        foo = self.bug.cf_internal_whiteboar
                        foo = foo.replace(f", {NO_TICKETS_KW}", "").replace(NO_TICKETS_KW, "")
                        self.bug.cf_internal_whiteboard = foo
                        print("    NoCustomerTickets flag removed")
                        # TODO: Why are we updating the bug here?
                        self.bz_api.update_bugs(self.bug.id,
                                                {'cf_internal_whiteboard': self.bug.cf_internal_whiteboard,
                                                 'nomail': 1})
        if ticket_open == 0 and ticket_count != 0:
            if NO_TICKETS_KW not in self.bug.cf_internal_whiteboard:
                if self.bug.cf_internal_whiteboard.strip() == "":
                    self.bug.cf_internal_whiteboard = NO_TICKETS_KW
                else:
                    self.bug.cf_internal_whiteboard = f"{self.bug.cf_internal_whiteboard}, {NO_TICKETS_KW}"
                print("    NoCustomerTickets flag added")
                # TODO: Why are we updating the bug here?
                self.bz_api.update_bugs(self.bug.id,
                                        {'cf_internal_whiteboard': self.bug.cf_internal_whiteboard, 'nomail': 1})
        score = ticket_count * ticket_totals
        if score:
            self.debug_msg(f"Calculation debugs: Tickets: {score}")
        return score

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

    def update(self):
        """perform score calculation and then update bug with new score"""
        score = self.score or self.calc_score()  # do not calculate again if we already have the score
        print(f"    New Score   = {score}")
        self.debug_msg(f"    Old Score   = {int(self.bug.cf_pm_score)}")
        if int(self.bug.cf_pm_score) != score:
            self.bz_api.update_bugs(self.bug.id, {'cf_pm_score': score, 'nomail': 1})
            print("    New score was updated")
        else:
            print("    New score was not updated")


def utc_format(dt, timespec='milliseconds'):
    """convert datetime to string in UTC format (YYYY-mm-ddTHH:MM:SS.mmmZ)"""
    iso_str = dt.astimezone(datetime.timezone.utc).isoformat('T', timespec)
    return iso_str.replace('+00:00', 'Z')


def parse_arguments():
    parser = argparse.ArgumentParser(description=f'{__file__} command line arguments')
    parser.add_argument('-k', '--key', required=True, type=str, action=EnvDefault,
                        envvar='BZ_API_KEY',
                        help='The Bugzilla API key')
    parser.add_argument('-p', '--time_delta_param', required=False, type=str, action=EnvDefault,
                        envvar='TIME_DELTA_PARAM',
                        help='The time delta parameter: hours or days')
    parser.add_argument('-v', '--time_delta_value', required=False, type=int, action=EnvDefault,
                        envvar='TIME_DELTA_VALUE',
                        help='The time delta value: number of [hours|days]. '
                             'For hours use 1 to 23, and for days use 1 to 30.')
    args = parser.parse_args()

    # check time delta arguments are valid
    valid_time_delta_params = ['hours', 'days']
    valid_hours = [1, 23]
    valid_days = [1, 30]

    if args.time_delta_param is not None and args.time_delta_param not in valid_time_delta_params:
        parser.error(f"Invalid time_delta_param. Valid values include: {valid_time_delta_params}")

    if args.time_delta_param is not None and args.time_delta_value is None:
        parser.error("The time_delta_value must be specified")

    if args.time_delta_param == "hours" and not valid_hours[0] <= args.time_delta_value <= valid_hours[1]:
        parser.error(f"For hours use values from {valid_hours[0]} to {valid_hours[1]}")

    if args.time_delta_param == "days" and not valid_days[0] <= args.time_delta_value <= valid_days[1]:
        parser.error(f"For days use values from {valid_days[0]} to {valid_days[1]}")

    # use time delta arguments
    if args.time_delta_param is not None and args.time_delta_value is not None:
        # convert time delta into UTC formatted string representing a time in the past according to the specified delta
        if args.time_delta_param == "hours":
            delta = datetime.datetime.now() - datetime.timedelta(hours=args.time_delta_value)
        else:
            delta = datetime.datetime.now() - datetime.timedelta(days=args.time_delta_value)
        last_change_time = utc_format(delta, timespec='seconds')
    else:
        last_change_time = None

    return args.key, last_change_time


def main(key, last_change_time=None):
    bz_api = RHBugzilla(url=URL, api_key=key)

    bz_bsu = BZBugScoreUpdater(bz_api)
    bz_bsu.perform_bug_score_updates(last_change_time)


if __name__ == "__main__":
    try:
        main(*parse_arguments())
    except Exception as exc:
        print(f"exception in main... {exc}")
