# this is an example for a crontab entry
# copy and past the lines below
# insert into your crontab config by running "crontab -e" and pasting into the doc.

# -----------------------
# PM Score Update
# -----------------------
# remove log file every couple of days
0 12 * * 1,3,5 rm /tmp/pmscalc.log
#update the pm score every hour from 6 AM to 6 PM (local time) 
0 6-18 * * * echo "$(date)">> /tmp/pmscalc.log 2>&1; . ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"  -p hours -v 1 > $PMSCALC_OUT; if [ $? -eq 0 ]; then echo "$(date): success!">> /tmp/pmscalc.log 2>&1; else echo "$(date): something bad happened">> /tmp/pmscalc.log 2>&1; fi; rm $PMSCALC_OUT;                                                                                                                             