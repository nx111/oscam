#!/bin/sh
#emuname=oscam

CAMD_BIN=oscam

remove_tmp () {
  rm -rf /tmp/*.info* /tmp/*.tmp*
}

case "$1" in
  start)
  remove_tmp
  /var/bin/$CAMD_BIN -b -c /var/tuxbox/config/oscam
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
