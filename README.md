egctl, Copyright (c) 2014, 2017, 2023 Vitaly Sinilin <vs@kp4.ru>
Published under the terms of the MIT License.

egctl is a program to control the state of EnerGenie Programmable
surge protector with LAN/WLAN interface. It uses native data exchange
protocol of the device, not HTTP.


## Installation

    make
    make install

will install in /usr/local. To use another prefix:

    PREFIX=/usr make install

The Makefile also understands `DESTDIR`.

## Supported devices

Currently the following devices are supported:
* EG-PMS-LAN
* EG-PM2-LAN
* EG-PMS2-LAN
* EG-PMS-WLAN


## Thanks to

Mārtiņš Brīvnieks for testing with EG-PMS2-LAN.
Philipp Kolmann for reporting about compatibility with EG-PM2-LAN.
joanandk for investigation of the EG-PMS-WLAN protocol.
