#!/usr/local/bin/bash
set -e

NAME="$*"

hccontrol le_enable enable
# May already be enabled
hccontrol le_set_scan_enable enable || true
sleep 1

ADDR=($(hccontrol read_neighbor_cache | \
        awk -vname="$NAME" '/[RP] / {type = $1; addr = $2} tolower($0)~("name: " tolower(name)) {print type, addr}'))
if [ "${ADDR[0]}" = R ]; then
	BTADDR=-r
fi
BTADDR="$BTADDR ${ADDR[1]}"
echo Connecting to Bluetooth address ${ADDR[1]}...

hccontrol le_set_scan_enable disable

lepair/lepair $BTADDR >hcsecd.conf

# reads hcsecd.conf always from the current dir
lesecd/lesecd &
LESECD_PID=$!
trap "kill $LESECD_PID" EXIT HUP TERM INT

sleep 1

rm -f hoge.db
nice -n -5 lehid/lehid -s $BTADDR
