# FreeBSD Bluetooth low energy, LE, tools

This repository contains Bluetooth LE related userland tools for
FreeBSD.
Kernel support was already committed to main trunk.

BLE support was written by Takanori Watanabe.
This repository/branch is just a collection of hacks to support more devices
and easy pairing.

## Utilities available

* le_enable <br>
	Enable and scan Bluetooth LE device. If the Bluetooth address is given
	as argument, connect attribute channnel and fetch all
	attribute informations and value as long as it can.

* lepair <br>
	Pairing tool. Give the Bluetooth address as an argument. It negotiates
	pairing parameter with the device through Security Manager Protocol.
	And requests or displays the PIN number. If PIN code authentication is
	valid, show the encryption parameters: EDIV, Random number, 128bit key.

* lesecd <br>
	Bluetooth LE security daemon. Read the configuration file hcsecd.conf
	in current directory. It starts encryption for incoming BLE
	connection request.

* lehid <br>
	Bluetooth LE client program.
	lehid 11:22:33:44:55:66
	will try to connect peer BLE device that have public address
	11:22:33:44:55:66.
	With -s option, wait channel connection until encryption was
	successfully set up.
	With -r option it will trying to connect random address.
	Client program example is batt.c.
	It supports Bluetooth HOGP mouse. If you want to use it,
	you have to pair by lepair and configure and run lesecd.

## How to compile under FreeBSD

    make
    make install

## Pairing a HID Device

All of these commands should be run as the root user.

First scan for the device.
Instead of `le_enable` which only shows one device, you might want to use `hccontrol`:

    hccontrol le_enable enable
    hccontrol le_set_scan_enable enable
    hccontrol read_neighbor_cache
    hccontrol le_set_scan_enable disable

The first character on the line before the bluetooth address tells you whether it has
a public or random address (`P` or `R`).
Then call the pairing utility.
If the device has a public address:

    lepair <ADDR> >hcsecd.conf

If it has a remote address, add the `-r` parameter in front of the _ADDR_.

If successful, you can now run the security daemon from the same directory:

    lesecd

In another terminal, run the client utiliy:

    lehid -s <ADDR>

If the _ADDR_ is random, use `-r` again as above.

To ease the process of pairing, you can use the `./hid-pair.sh` script:

    ./hid-pair.sh <NAME>

Where _NAME_ is the user-readable name of the device - run the discovery commands above if you are not sure about it.
For instance `./hid-pair.sh ELECOM TrackBall` can be used to pair an Elecom Bitra trackball.
On the downside, the device must always be in pairing mode before you run this command.

## Troubleshooting

If the mouse pairs, but lags and you have a combined Wifi+Bluetooth module, try another Wifi driver.
I found the legacy `if_iwm` driver to cause such problems on my Intel(R) Dual Band Wireless AC 8265.
It can be fixed by adding the following to rc.conf:

    devmatch_enable="YES"
    devmatch_blocklist="if_iwm"

In case the mouse does not pair properly, please create a ticket in this repository and include the following information:

* A log, created with `hcidump -w bug.cap`, while running the `hid-pair.sh` script.
* The complete output of the `hid-pair.sh` script.
* `hcsecd.conf`
* `hoge.db`
