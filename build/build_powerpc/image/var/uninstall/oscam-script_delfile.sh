#!/bin/sh

killall -9 oscam 2>/dev/null
sleep 2

rm -f /var/uninstall/oscam-script_delfile.sh
rm -f /var/uninstall/oscam_delete.sh
rm -f /var/uninstall/oscam-complete_delfile.sh
rm -f /var/etc/plimgr/cams/oscam
exit 0

######################################
####### Powered by Gemini Team #######
## http://www.i-have-a-dreambox.com ##
######################################
