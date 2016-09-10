#!/bin/sh

killall -9 oscam 2>/dev/null
sleep 2
remove_tmp

rm -f /usr/script/oscam_cam.sh
rm -f /usr/uninstall/oscam-script_delfile.sh
rm -f /etc/init.d/softcam.oscam
exit 0

######################################
####### Powered by Gemini Team #######
## http://www.i-have-a-dreambox.com ##
######################################
