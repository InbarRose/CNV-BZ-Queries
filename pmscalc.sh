# this file contains examples of how to run the script to calculate and the pm score field


#update all bugs
. ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"

#update bugs modified in the last hour and keep logs
echo "$(date)">> /tmp/pmscalc.log 2>&1; . ~/pmscalc_vars; /usr/bin/python "$PMSCALC_SCRIPT" -k "$PMSCALC_BZ_KEY"  -p hours -v 1 > $PMSCALC_OUT; if [ $? -eq 0 ]; then echo "$(date): success!">> /tmp/pmscalc.log 2>&1; else echo "$(date): something bad happened">> /tmp/pmscalc.log 2>&1; fi; rm $PMSCALC_OUT;

