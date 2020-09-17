# CNV-BZ-Queries
This repo contains a list of scripts used to obtain/update information in bugzilla.

## PM Score Calculation
*pm_score_calc_cnv.py:* This script updates the pm score for the bugs returned by a specified Jira Query. The script can be scheduled as a cron job to fetch and update a set of bugs based on their last update timestamp.


## Pre-Requisites
### Python
Install bugzilla module. You may need to do this using 
```
dnf install python3-bugzilla
  or
sudo dnf install python3-bugzilla
```
### Bugzilla
* A bugzilla account with rights to update the cf_pm_score field.
* A bugzilla API Key. See *Creating a Bugzilla API Key* for instructions on how to do this.

## Useful Info
### Environment setup

I recommend setting up the environment prior to executing **pm_score_calc_cnv.py**, this will help you test things out to automate script execution. Use [pmscalc_vars.sh](https://github.com/thenaggster/CNV-BZ-Queries/blob/master/pmscalc_vars.sh) as an example. 

```
#script directory
export PMSCALC_HOME="<YOUR_SCRIPT_DIRECTORY>"

#the actual script
export PMSCALC_SCRIPT="$PMSCALC_HOME/pm_score_calc_cnv.py"

#Bugzilla API Key - make sure that your account has the access to update the "cf_pm_score field"
#you can get this one from https://<your-bugzilla-instance>/userprefs.cgi?tab=apikey
export PMSCALC_BZ_KEY="<MY_BZ_API_KEY>"

#output file for debugging purposes (generated each run)
export PMSCALC_OUT=`echo $(uuidgen;)$(echo '_pmscalc.csv';)`;
```

### Script Execution

```
usage: pm_score_calc_cnv.py [-h] -k KEY [-p TIME_DELTA_PARAM] [-v TIME_DELTA_VALUE]
  -h, --help            show this help message and exit
  -k KEY, --key KEY     The Bugzilla API key
  -p TIME_DELTA_PARAM, --time_delta_param TIME_DELTA_PARAM
                        The time delta parameter: hours or days
  -v TIME_DELTA_VALUE, --time_delta_value TIME_DELTA_VALUE
                        The time delta value: number of [hours|days].  
                        For hours use 1-23, and for days use 1-30.
```


Below are some examples of how you may run the script. These are contained in [pmscalc.sh](https://github.com/thenaggster/CNV-BZ-Queries/blob/master/pmscalc.sh).

```
#update all bugs
. ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"

#update bugs modified in the last hour and keep logs
echo "$(date)">> /tmp/pmscalc.log 2>&1; . ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"  -p hours -v 1 > $PMSCALC_OUT; if [ $? -eq 0 ]; then echo "$(date): success!">> /tmp/pmscalc.log 2>&1; else echo "$(date): something bad happened">> /tmp/pmscalc.log 2>&1; fi; rm $PMSCALC_OUT;

#update bugs modified in the last 7 days and keep logs
echo "$(date)">> /tmp/pmscalc.log 2>&1; . ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"  -p days  -v 7 > $PMSCALC_OUT; if [ $? -eq 0 ]; then echo "$(date): success!">> /tmp/pmscalc.log 2>&1; else echo "$(date): something bad happened">> /tmp/pmscalc.log 2>&1; fi; rm $PMSCALC_OUT;
```

### Script Execution Automation

Below is an example showing how you could automate the script execution. 

```
# copy and past the lines below
# insert into your crontab config by running "crontab -e" and pasting into the doc.

# -----------------------
# PM Score Update
# -----------------------
# remove log file every couple of days
0 12 * * 1,3,5 rm /tmp/pmscalc.log
#update the pm score every hour from 6 AM to 6 PM (local time)
0 6-18 * * * echo "$(date)">> /tmp/pmscalc.log 2>&1; . ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"  -p hours -v 1 > $PMSCALC_OUT; if [ $? -eq 0 ]; then echo "$(date): success!">> /tmp/pmscalc.log 2>&1; else echo "$(date): something bad happened">> /tmp/pmscalc.log 2>&1; fi; rm $PMSCALC_OUT;                                                                                                                            
```
## Creating a Bugzilla API Key
1. Visit[ https://bugzilla.redhat.com/userprefs.cgi?tab=apikey](https://bugzilla.redhat.com/userprefs.cgi?tab=apikey) and generate new api_key by checking the checkbox below and entering optional description
2. write down you api_key, you won't be able to access it again
3. create ~/.config/python-bugzilla/bugzillarc containing

    ```
    [bugzilla.redhat.com?]
    api_key=YOUR_API_KEY
    ```
4. check if ~/.cache/python-bugzilla/bugzillacookies exists and if yes, delete (ONLY) the line specifying the cookie and leave comments alone.

5. delete if exists
       ~/.cache/python-bugzilla/bugzillatoken
       ~/.bugzillatoken
       ~/.bugzillacookie
