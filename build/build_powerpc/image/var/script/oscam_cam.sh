#!/bin/sh
########################################
###### Powered by The Gemini Team ######
### http://www.i-have-a-dreambox.com ###
########################################
#  camid                               #
#  0000       = Commom Interface       #
#  0001->0099 = for User Experiment    #
#  0177       = Rq-Echo-Client         #
#  0178       = RqCS                   #
#  0179       = RqCamd                 #
#  0189       = OpenCam                #
#  0199       = Dccamd                 #
#  0200->0299 = Fbiss                  #
#  0300->0399 = Camd3                  #
#  0400->0499 = Camx                   #
#  0500->0599 = Camx-Radegast-CS       #
#  0600->0699 = Evocamd           -OLD #
#  0700->0799 = Evocamd_ronlad_cs -OLD #
#  0800->0899 = Mgcamd            -OLD #
#  0900->0999 = Mgcamd_ronald_cs  -OLD #
#  1000->1099 = Newcamd           -OLD #
#  1100->1199 = Newcamd-ronald_CS -OLD #
#  1200->1299 = Newcamd-spider    -OLD #
#  1300->1399 = Radegast               #
#  1400->1499 = Ronald-CS              #
#  1500->1599 = Scam                   #
#  1600->1699 = Scam-Ronald-CS         #
#  1700->1799 = OSCam                  #
#  1800->1899 = NewCS                  #
#  2000->2099 = Camd3                  #
#  2300->2399 = Camd3-NewCS            #
#  2600->2699 = Camd3-MPCardserver     #
#  3000->3099 = Evocamd                #
#  3100->3199 = Evocamd-Ronald-CS      #
#  3200->3299 = Evocamd-NewCS          #
#  3300->3399 = Evocamd-MPCardserver   #
#  4000->4099 = Mgcamd                 #
#  4100->4199 = Mgcamd-Ronald-CS       #
#  4200->4299 = Mgcamd-NewCS           #
#  4300->4399 = Mgcamd-OSCam           #
#  5000->5099 = Newcamd-Betad          #
#  5100->5199 = Newcamd-Cardserver     #
#  5200->5299 = Newcamd-Spider         #
#  5300->5399 = Newcamd-NewCS          #
#  5400->5499 = Newcamd-OSCam          #
#  6000->6099 = CCcam                  #
#  6100->6199 = CCcam-Capmtserver      #
#  6200->6299 = CCcam-NewCS            #
#  6300->6399 = CCcam-OSCam            #
#  7000->7099 = Mbox                   #
#  7100->7199 = Mbox-NewCS             #
#  9500->9599 = reserved               #
#  9600->9699 = reserved               #
#  9700->9799 = reserved               #
#  9800->9899 = reserved               #
#  9900->9999 = reserved               #
########################################

CAMD_ID=1700
CAMD_NAME="OSCam"
CAMD_BIN=oscam

INFOFILE_A=ecm.info
INFOFILE_B=ecm.info
INFOFILE_C=ecm.info
INFOFILE_D=ecm.info
#Expert window
INFOFILE_LINES=1111111111000000
#Zapp after start
REZAPP=0

logger $0 $1
echo $0 $1

remove_tmp () {
  rm -rf /tmp/*.info* /tmp/*.tmp*
}

case "$1" in
  start)
  remove_tmp
  /var/bin/$CAMD_BIN -c /var/tuxbox/config -b
  ;;
  stop)
  killall $CAMD_BIN 2>/dev/null
  sleep 2
  killall -9 $CAMD_BIN 2>/dev/null
  remove_tmp
  ;;
  *)
  $0 stop
  exit 0
  ;;
esac

exit 0
