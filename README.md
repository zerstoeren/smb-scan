SMB-Scan - This is a complete rewrite v2 of the original by Crypt0s. Thanks to him for starting the project.  Read below.
========

Python-based SMB Share scanner -- scans a bunch of computers, outputs the file share, SMB version, and some banner information when available.

Just a note is that I kind of started a re-write of this because of some other areas that I would eventually like to take this code in the future.

Lesson Learned
===

One lesson learned when forking this tool and re-writing sections is that even though SMB can find shares, port 445 isn't always open so this fork will let you know if shares are available and if port 445 is open it will present the
banner grab information in the output.  Otherwise, a closed message occurs.  I have also learned that in certain configurations, both port will be open or just port 445 depending on whether or not SMB has been configured with NetBIOS to broadcast the shares.  I have also found configurations where the SMB banners are presented on both ports, but this scanner should pick that up and let you know what's what.  There is a lot further we can take this project in the future since SMB and WINS hooks are known.  More research and additions to this scanner to come in the future.

The actual SMB shares are found over port 139.
because NetBIOS is actually the protocol broadcasting the shares.  I learned this while watching tcpdump and getting a deep 
review of the smbc library.  It's interesting, so there are 2 different messages based on what the scanner detects.  :)

Also note 2 different SMB libraries and this is because they work in different ways and consider different functionality.  pysmb I found to be better and faster for part of the scan while pysmbc did a better job for other parts.  The two together cover everything that we need currently and for a while into the future though. :)

Example:

My Samba docker container is off in this example:

```bash
root@docker# ./smbscanner.py -ip 192.168.10.5
attempting to scan 192.168.10.5
root@docker#
```
This is the output with my docker container turned on:

```
root@docker# ./smbscanner.py -ip 192.168.10.5
attempting to scan 192.168.10.5

[+] 192.168.10.5: <smbc.Dirent object "print$" (File share) at 0x7f0571659e40>, Port 445: closed, Possible DPulsar Target = 
False

[+] 192.168.10.5: <smbc.Dirent object "IPC$" (IPC share) at 0x7f0571659e90>, Port 445: closed, Possible DPulsar Target = False
root@docker:~/smb-scan# 
```

In the event that port 445 is open, the banner will present itself in the output.

If you use the "-results_file" flag, you should get a nice parseable output:

The file should look like the following:

```
host: 192.168.10.5

is_smb: true

open_share:<smbc.Dirent object "print$" (File share) at 0x7feaf9721ee0>

banner: closed

is_dpulsar: false

bg_port: 445

timestamp: 1498609377.92

host: 192.168.10.5

is_smb: true

open_share:<smbc.Dirent object "IPC$" (IPC share) at 0x7feaf9721f30>

banner: closed

is_dpulsar: false

bg_port: 445

timestamp: 1498609377.92
```

Dependencies:
=============

https://pypi.python.org/pypi/pysmbc/

netaddr

pysmb 

Usage:
======

```bash
./smbscanner.py -h
```

SMB Checker
  
Example
===

```bash
./smbscanner.py -ip 192.168.10.5

./smbscanner.py -netrange 192.168.10.0/24 -results_file results.txt
```

Bugs
====

- can now find SMB with good configuration - fixed
- tests SMB on port 139 and 445 - fixed
- tests SMB versions - fixed
- ICMP for SMB to speed things up a bit - fixed
- you can now read in a target file - fixed
- issues were only reported upon finding open shares - fixed
- added echo to detect smb resonses in event of a good configuration - fixed


TODO
===


add credentials

add anonymous

add null session testing

If you find other bugs that I haven't mentioned, please report them to gmail (rlastinger) or create a ticket, and I will get to it when I can.  

Help or improvement suggestions are also welcome.  Just email me at gmail (rlastinger).

Credits to Twitter (@crypt0s) or gmail (Bryanhalf) for the original project that I forked to start this one.
Thanks for starting this project Bryan.
Enjoy.
