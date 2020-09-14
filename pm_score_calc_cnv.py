#!/usr/bin/env python

from __future__ import division, print_function
import ssl
from parser import parser

from pdb import set_trace
# import bugzilla

from bugzilla.rhbugzilla import RHBugzilla

import sys
from datetime import datetime, timezone, timedelta

import argparse
import os

class EnvDefault(argparse.Action):
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if not default and envvar:
            if envvar in os.environ:
                default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required,
                                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

URL = "bugzilla.redhat.com"
NOTICKETS_KW = "NoActiveCustomerTickets"

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


class BugScore(object):
    def __init__(self, bz_id):

        self.bug = bzapi.getbug(bz_id, include_fields=['_default','_custom','flags','external_bugs'])

    def calc_regression(self):
        score = 0
        if 'Regression' in self.bug.keywords:
            score = REGRESSION
        #if score:
            #print("Calculation debugs: Regression keyword: {}".format(score))
        return score

    def calc_blocker(self):
        score = 0
        if self.bug.get_flag_status('blocker') is not None:
            score = BLOCKER
        #if score:
            #print("Calculation debugs: Blocker: {}".format(score))
        return score

    def calc_automation_blocker(self):
        score = 0
        if 'AutomationBlocker' in self.bug.keywords:
            score = AUTOMATION_BLOCKER
        #if score:
        #    print("Calculation debugs: Automation Blocker: {}".format(score))
        return score

    def calc_cee(self):
        score = 0
        # print('INTERNAL: %s' % self.bug.cf_internal_whiteboard)
        if 'CEEBumpPMScore' in self.bug.cf_internal_whiteboard:
            score = CEEBumpPMScore
        #if score:
        #    print(
        #        "Calculation debugs: CEEBumpPMScore internal whiteboard: {}".format(score))
        return score

    def calc_cirflag(self):
        score = 0
        if self.bug.get_flag_status('cee_cir') == '+':
            score = CIR_FLAG
        #if score:
        #    print("Calculation debugs: cee_cir+ flag: {}".format(score))
        return score

    def calc_ceecir(self):
        score = 0
        if 'CEECIR' in self.bug.cf_internal_whiteboard:
            internal_whiteboard = self.bug.cf_internal_whiteboard.split()

            for x in internal_whiteboard:
                if "CEECIR" in x:
                    set_trace()
                    score = int(x.strip(",").strip("CEECIR_"))
        #if score:
        #    print("CalculatiThe only thing I have a question on is finding info about the on debugs: CEECIR_x in internal whiteboard: {}".format(score))
        return score

    def calc_severity(self):
        #if self.bug.severity != "unspecified":
        #    print("Calculation debugs: Severity score: {}".format(SEVERITY_SCORE[self.bug.severity]))
        return SEVERITY_SCORE[self.bug.severity]

    def calc_priority(self):
        #if self.bug.priority != "unspecified":
        #    print("Calculation debugs: Priority score: {}".format(PRIORITY_SCORE[self.bug.priority]))
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
                    if NOTICKETS_KW in self.bug.cf_internal_whiteboard:
                        foo = self.bug.cf_internal_whiteboar
                        foo = foo.replace(", "+NOTICKETS_KW, "").replace(NOTICKETS_KW, "")
                        self.bug.cf_internal_whiteboard = foo
                        print("    NoCustomerTickets flag removed")
                        bzapi.update_bugs(self.bug.id, {
                            'cf_internal_whiteboard': self.bug.cf_internal_whiteboard,
                            'nomail': 1}
                        )
        if ticket_open == 0 and ticket_count != 0:
            if NOTICKETS_KW not in self.bug.cf_internal_whiteboard:
                if self.bug.cf_internal_whiteboard.strip() == "":
                    self.bug.cf_internal_whiteboard = NOTICKETS_KW
                else:
                    self.bug.cf_internal_whiteboard = self.bug.cf_internal_whiteboard + ", " + NOTICKETS_KW
                print("    NoCustomerTickets flag added")
                bzapi.update_bugs(self.bug.id, {
                    'cf_internal_whiteboard': self.bug.cf_internal_whiteboard,
                    'nomail': 1}
                )
        score = ticket_count * ticket_totals
        #if score:
        #    print("Calculation debugs: Tickets: {}".format(score))
        return score

    def calc_score(self):
        score = list()
        score.append(self.calc_regression())
        score.append(self.calc_blocker())
        score.append(self.calc_severity())
        score.append(self.calc_priority())
        score.append(self.calc_tickets())
        score.append(self.calc_automation_blocker())
        score.append(self.calc_cee())
        score.append(self.calc_cirflag())
        return sum(score)

    def update(self):
        score = self.calc_score()
        print("    New Score   = %s" % score)
        if int(self.bug.cf_pm_score) != score:
            bzapi.update_bugs(self.bug.id, {'cf_pm_score': score, 'nomail': 1})
            print("    New score was updated")
        else:
            print("    New score was not updated")

#verify parameters
# - must have specified... 
#   - config file
def verifyParameters():
    try:
        #print (len(sys.argv))
        if len(sys.argv) <= 1:
            #print("we are in trouble....")
            raise ValueError("invalid number of arguments...")
        else:
            pass
            #print("we are on a good path....")
            #raise Exception("Just testing...")
    except ValueError as e:
        print(str(e))
        print(getUsage())
        raise
    except Exception as e:
        print(str(e))
        print("Something else went wrong")
        raise

def getUsage():
    return "usage " + __file__ + "  <BUGZILLA_API_KEY>"

def utcformat(dt, timespec='milliseconds'):
    #"""convert datetime to string in UTC format (YYYY-mm-ddTHH:MM:SS.mmmZ)"""
    iso_str = dt.astimezone(timezone.utc).isoformat('T', timespec)
    return iso_str.replace('+00:00', 'Z')


def fromutcformat(utc_str, tz=None):
    iso_str = utc_str.replace('Z', '+00:00')
    return datetime.fromisoformat(iso_str).astimezone(tz)

def checkArguments():
    parser = argparse.ArgumentParser(description=__file__ + ' command line arguments')
    parser.add_argument('-k', '--key', required=True, type=str, action=EnvDefault, envvar='BZ_API_KEY',
                        help='The Bugzilla API key')
    parser.add_argument('-p', '--time_delta_param', required=False, type=str, action=EnvDefault, envvar='TIME_DELTA_PARAM',
                        help='The time delta parameter: hours or days')
    parser.add_argument('-v', '--time_delta_value', required=False, type=int, action=EnvDefault, envvar='TIME_DELTA_VALUE',
                        help='The time delta value: number of [hours|days]. For hours use 1 to 23, and for days use 1 to 30.')
    args = parser.parse_args()

    #check passed arguments
    valid_time_delta_params = ['hours','days']
    valid_hours = [1,23]
    valid_days = [1,30]

    errormessage = ""

    if args.time_delta_param != None:
        if args.time_delta_param in valid_time_delta_params:
            if args.time_delta_value == None:
                    errormessage = "The time_delta_value must be specified"
            else:
                if args.time_delta_param == "hours":
                    if args.time_delta_value < valid_hours[0] or args.time_delta_value > valid_hours[1]:
                        errormessage = "For hours use values from " + str(valid_hours[0]) + " to " + str(valid_hours[1])
                else:
                    if args.time_delta_value < valid_days[0] or args.time_delta_value > valid_days[1]:
                        errormessage = "For days use values from " + str(valid_days[0]) + " to " + str(valid_days[1])
        else:
            errormessage = "Invalid time_delta_param. Valid values include: " + str(valid_time_delta_params)

    if errormessage != "":
        print(errormessage)
        parser.print_help()
        parser.exit(1)
    else:
        return args


if __name__ == "__main__":
#    main()

#def main():
#verify parameters
    try:
        args = checkArguments()
        in_api_key = args.key

        #_user = "rgarcia@redhat.com"
        #_password = "R3dH4t4M32!"
        #bzapi = RHBugzilla(url=URL, user=_user, password=_password)

        bzapi = RHBugzilla(url=URL,api_key=in_api_key)

        query_old = {
            'bug_status': [
                'NEW', 'ASSIGNED', 'POST', 'MODIFIED', 'ON_QA', 'VERIFIED'
            ],
            #'f1': 'OP',
            'f2': 'product',
            #'f3': 'classification',
            #'f4': 'CP',
            #'f5': 'OP',
            # 'f6': 'days_elapsed',
            #'f6': 'delta_ts',
            #'j1': 'OR',
            'o2': 'equals',
            #'o3': 'equals',
            # 'o6': 'lessthaneq',
            #'o6': 'greaterthaneq',
            'v2': 'Container Native Virtualization (CNV)',
            #'v2': 'Red Hat Enterprise Virtualization Manager',
            #'v3': 'oVirt',
            # 'v6': '1'
            #'v6': '-1h'
        }

        query = {
            'bug_status': [
                'NEW', 'ASSIGNED', 'POST', 'MODIFIED', 'ON_QA', 'VERIFIED'
            ],
            'product':'Container Native Virtualization (CNV)',
            'include_fields':['_default','_custom','flags','external_bugs']
        }

        #check to see if the user specified a time delta for the query
        lastchangetime = datetime.now()
        if args.time_delta_param != None:
            if args.time_delta_param == "hours":
                lastchangetime = lastchangetime - timedelta(hours=args.time_delta_value)
            else:
                lastchangetime = lastchangetime - timedelta(days=args.time_delta_value)
            query['last_change_time'] = utcformat(lastchangetime,timespec='seconds')

        bugs = bzapi.query(query)
        print ("Number of BZ to update: %s" % len(bugs))
        print("Bug ID, before, after")
        i = 1
        for bug in bugs:
            #print(str(i) + "," + str(bug.id))
            #print(bug._bug_fields)
            bz = BugScore(bug.id)
            print(str(i) + "," + str(bug.id) + "," + bug.cf_pm_score + "," + str(bz.calc_score()))
            bz.update()
            i = i + 1
    except Exception as e:
        print("exception in main..." + str(e))
