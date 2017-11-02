# SSH version and host key monitor

This script scans and compare ssh version and host keys with the previous
records. It sends alert email when the ssh version or host key is different from
last scan.


# Requirement

Python2.7, python-nmap, and the latest nmap. Nmap(version 6.47) comes with
Debian Jessie won't work because a bug. Nmap that work well include version
7.40(from Debian Stretch) and 7.60(latest version as of Oct 2017).


# Usage

Config the email setting in config.json, add target hosts, then run it either
manually, or from cron.
