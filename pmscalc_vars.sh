# Use this script to define the environment variables needed by your script.
# These are specially useful to be able to run this script in a cron job.

#script directory
export PMSCALC_HOME="<YOUR_SCRIPT_DIRECTORY>"

#the actual script
export PMSCALC_SCRIPT="$PMSCALC_HOME/pm_score_calc_cnv.py"

#Bugzilla API Key - make sure that your account has the access to update the "cf_pm_score field"
#you can get this one from https://<your-bugzilla-instance>/userprefs.cgi?tab=apikey
export PMSCALC_BZ_KEY="<MY_BZ_API_KEY>"

#output file for debugging purposes (generated each run)
export PMSCALC_OUT=`echo $(uuidgen;)$(echo '_pmscalc.csv';)`;