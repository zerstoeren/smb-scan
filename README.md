SMB-Scan - This is a forked beta version, but is functional for most flags that are currently implemented.  Read below.
========

Python-based SMB Share scanner -- scans a bunch of computers, outputs the path and the file permissions for the account

Just a note is that I kind of started a re-write of this because of some other areas that I would eventually like to take this code in the future.

Lesson Learned
===

One lesson learned when forking this tool and re-writing sections is that even though SMB can find shares, port 445 iisn't always open so this fork will let you know if shares are available and if port 445 is open it will present the
banner grab information in the output.  Otherwise, a closed message occurs.  

The actual SMB shares are found over port 139
because NetBIOS is actually the protocol broadcasting the shares.  I learned this while watching tcpdump and getting a deep 
review of the smbc library.  It's interesting, so there are 2 different messages based on what the scanner detects.  :)

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


TODO
===

add the abiltity to read target files.

add credentials

add anonymous

add null session testing

If you find other bugs that I haven't mentioned, please report them to gmail (rlastinger) or create a ticket, and I will get to it when I can.  

Help or improvement suggestions are also welcome.  Just email me at gmail (rlastinger).

Credits to Twitter (@crypt0s) or gmail (Bryanhalf) for the original project that I forked to start this one.
Thanks for starting this project Bryan.
Enjoy.
