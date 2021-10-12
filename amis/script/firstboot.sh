#!/bin/bash

yum install bind-utils -y
rpm --import /etc/pki/rpm-gpg/*
yum clean all
yum install ed -y
yum install aide -y
# SNMP
yum install net-snmp -y
# MCELOGD
yum install mcelog -y

sed -i 's/^AllowGroups/#AllowGroups/' /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

sed -i 's/Subsystem sftp    \/usr\/libexec\/openssh\/sftp-server/Subsystem       sftp    \/usr\/libexec\/openssh\/sftp-server/' /etc/ssh/sshd_config
# NPROC ULIMIT
echo "* hard core 0" >> /etc/security/limits.d/20-nproc.conf
#
systemctl mask NetworkManager
systemctl stop NetworkManager
systemctl disable NetworkManager
#
# Disable netconfig rules for tcp6 and udp6
ed -s /etc/netconfig <<< $'g/tcp6/d\nw'
ed -s /etc/netconfig <<< $'g/udp6/d\nw'
#
# SELinux configuration
#sed -i 's/^\(SELINUX\)=.*/\1=permissive/' /etc/selinux/config
#setenforce permissive
#
# Enable/Disable modules
<< EOF cat > /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install udf /bin/true
install vfat /bin/true
options ipv6 disable=1
EOF

#
# RSysLog configuration
<< EOF cat >/etc/rsyslog.conf
# rsyslog v5 configuration file
# For more information see /usr/share/doc/rsyslog-*/rsyslog_conf.html
# If you experience problems, see http://www.rsyslog.com/doc/troubleshoot.html
\$FileCreateMode 0640

#### MODULES ####
\$ModLoad imuxsock # provides support for local system logging (e.g. via logger command)
\$ModLoad imklog   # provides kernel logging support (previously done by rklogd)
\$ModLoad imtcp
#\$InputTCPServerRun 514

# Use default timestamp format
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Include all config files in /etc/rsyslog.d/
\$IncludeConfig /etc/rsyslog.d/*.conf

#### RULES ####
# Don't log private authentication messages!
*.info;mail.none;authpriv.none;cron.none                        /var/log/messages

# The authpriv file has restricted access.
authpriv.*                                                      /var/log/secure

# Log all the mail messages in one place.
mail.*                                                          -/var/log/maillog

# Log cron stuff
cron.*                                                          /var/log/cron

# Everybody gets emergency messages
*.emerg                                                         *

# Save news errors of level crit and higher in a special file.
uucp,news.crit                                                  /var/log/spooler

# Save boot messages also to boot.log
local7.*                                                        /var/log/boot.log

# ### end of the forwarding rule ###

# A template to for higher precision timestamps + severity logging
\$template SpiceTmpl,"%TIMESTAMP%.%TIMESTAMP:::date-subseconds% %syslogtag% %syslogseverity-text%:%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"
:programname, startswith, "spice-vdagent"       /var/log/spice-vdagent.log;SpiceTmpl
EOF
#
#
# Sysconfig init setup
sed -i 's/SINGLE=.*/SINGLE=\/sbin\/sulogin/' /etc/sysconfig/init
sed -i 's/PROMPT=.*/PROMPT=no/' /etc/sysconfig/init
echo "umask 027" >> /etc/sysconfig/init
#
# Disable coredump
echo "* hard core 0" >> /etc/security/limits.conf
#
#
# SYSCTL configuration
<< EOF cat > /etc/sysctl.conf
# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.
#
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
#
# Do not accept IPV6 adverts
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPV6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Controls source route verification
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Routing/forwarding restrictions
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.ip_forward = 0
net.ipv4.route.flush=1

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536

# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296
fs.suid_dumpable = 0

# ASLR
kernel.randomize_va_space = 2

EOF
#
# CRON/ANACRON permissions/ownership
chown root:root /etc/anacrontab
chmod 600 /etc/anacrontab
chown root:root /etc/crontab
chmod 600 /etc/crontab
chown root:root /etc/cron.hourly
chmod 700 /etc/cron.hourly
chmod 600 /etc/cron.hourly/*
chown root:root /etc/cron.daily
chmod 700 /etc/cron.daily
chmod 600 /etc/cron.daily/*
chown root:root /etc/cron.weekly
chmod 700 /etc/cron.weekly
chmod 600 /etc/cron.weekly/*
chown root:root /etc/cron.monthly
chmod 700 /etc/cron.monthly
chmod 600 /etc/cron.monthly/*
chown root:root /etc/cron.d
chmod 700 /etc/cron.d
chmod 600 /etc/cron.d/*
rm -f /etc/cron.deny
rm -f /etc/cron.allow
touch /etc/cron.allow
chown root:root /etc/cron.allow
chmod 600 /etc/cron.allow
#
# AT permissions/ownership
rm -f /etc/at.deny
rm -f /etc/at.allow
touch /etc/at.allow
chown root:root /etc/at.allow
chmod 600 /etc/at.allow
#
# Postfix configuration
<< EOF cat > /etc/postfix/main.cf
# Basic configuration of Postfix MTA for NVS

# Standard PATH definitions
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/libexec/postfix
data_directory = /var/lib/postfix
manpage_directory = /usr/share/man
sample_directory = /usr/share/doc/postfix-2.6.6/samples
readme_directory = /usr/share/doc/postfix-2.6.6/README_FILES
manpage_directory = /usr/share/man
html_directory = no

# Binary PATH definitions
sendmail_path = /usr/sbin/sendmail.postfix
newaliases_path = /usr/bin/newaliases.postfix
mailq_path = /usr/bin/mailq.postfix

# Postfix process ownership
mail_owner = postfix
setgid_group = postdrop

# Network environment setup
inet_interfaces = localhost
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost
unknown_local_recipient_reject_code = 550


# Aliases should stay empty in NVS environment
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases

# Debug vebosity configuration
debug_peer_level = 2
debugger_command =
         PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
         ddd $daemon_directory/$process_name $process_id & sleep 5
EOF
#
# Banner Setup
<< EOF cat > /etc/issue
|------------------------------------------------------------|
|  This system is for the use of authorized users only.      |
|  Use of this computer system, authorized or unauthorized,  |
|  constitutes consent to monitoring of this system. All     |
|  information, including personal information, placed on or |
|  sent over this system may be monitored. Unauthorized use  |
|  may subject you to criminal prosecution. Evidence of      |
|  unauthorized use collected during monitoring may be used  |
|  for administrative, criminal or adverse action. Use of    |
|  this system constitutes consent to monitoring for these   |
|  purposes. Use of any web/network tools must be limited to |
|  business use only. Web surfing is explicitly prohibited.  |
|------------------------------------------------------------|
EOF
chown root:root /etc/issue
chmod 644 /etc/issue
cp -p /etc/issue /etc/issue.net
yes | cp -pr  /etc/issue /var/lib/update-motd/motd
rm -rf /etc/motd
cp -pr /etc/issue /etc/motd
#
# PAM setup
echo "password  sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
echo "password  sufficient pam_unix.so remember=5" >> /etc/pam.d/password-auth
echo "auth       required       pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/password-auth
echo "auth       [success=1 default=bad] pam_unix.so"  >> /etc/pam.d/password-auth
echo "auth       [default=die]  pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/password-auth
echo "auth       sufficient     pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/password-auth
echo "auth       required       pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth       [success=1 default=bad] pam_unix.so"  >> /etc/pam.d/system-auth
echo "auth       [default=die]  pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth       sufficient     pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth
sed -i "s/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass retry=3/g" /etc/pam.d/system-auth
sed -i "s/password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=/password    requisite     pam_pwquality.so try_first_pass retry=3/g" /etc/pam.d/password-auth
sed -i "s/password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok=/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok=/g" /etc/pam.d/password-auth
sed -i "s/password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok=/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok=/g" /etc/pam.d/system-auth
sed -i "s/password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok=/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok=/g" /etc/pam.d/password-auth
sed -i "s/password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok=/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok=/g" /etc/pam.d/system-auth
sed -i "/pam_wheel.so use_uid/s/^# *//" /etc/pam.d/su

<< EOF cat > /etc/security/pwquality.conf
minlen=14
dcredit=-1
ucredit=-1
ocredit=-1
lcredit=-1
EOF
#

# Set default password policies
<< EOF cat > /etc/default/useradd
# useradd defaults file
GROUP=1000
HOME=/home
INACTIVE=30
EXPIRE=60
SHELL=/bin/bash
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes
EOF
#
### Make sure that audit logs aren't automatically deleted
sed -i "s/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g"  /etc/audit/auditd.conf
### Audit Rules
<< EOF cat > /etc/audit/rules.d/audit.rules
-D
-b 8192
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit arch=b64 -S init_module -S delete_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /var/run/faillock/ -p wa -k logins
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/localtime -p wa -k time-change
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ksu -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/cgexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/cgclassify -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/mount.nfs -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-e 2
EOF


# Security baselines additions
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' /etc/login.defs
sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN\t14/' /etc/login.defs
sed -i 's/umask.*/umask 027/' /etc/bashrc
sed -i 's/umask.*/umask 027/' /etc/profile
#
# Safeguard TCPDUMP
chmod 0500 /usr/sbin/tcpdump
chown root:root /usr/sbin/tcpdump
#
# Delete bogus default users
userdel gopher
userdel games
#
#
### Make sure that even boot will be audited
sed -i 's/quiet/audit=1 quiet/g' /etc/default/grub
grub2-mkconfig > /boot/grub2/grub.cfg
### Secure GRUB
chmod 600 /boot/grub2/grub.cfg
#
### Secure PASSWD
chmod 644 /etc/passwd
chmod 600 /etc/passwd-
#
### Secure GROUP
chmod 644 /etc/group
chmod 600 /etc/group-
#
### Suppress LVM FD warnings
<< EOF cat > /etc/profile.d/lvm.sh
set LVM_SUPPRESS_FD_WARNINGS=1
export LVM_SUPPRESS_FD_WARNINGS=1
EOF
#
### Update rc.local
chmod +x /etc/rc.d/rc.local
<< EOF cat > /etc/rc.d/rc.local
#!/bin/bash
# THIS FILE IS ADDED FOR COMPATIBILITY PURPOSES
#
# It is highly advisable to create own systemd services or udev rules
# to run scripts during boot instead of using this file.
#
# In contrast to previous versions due to parallel execution during boot
# this script will NOT be run after all other services.
#
# Please note that you must run 'chmod +x /etc/rc.d/rc.local' to ensure
# that this script will be executed during boot.
touch /var/lock/subsys/local
#
### CIS
find /var/log -type f -exec chmod 600 {} +
find /var/log -type d -exec chmod 700 {} +
sed -i 's/\/usr\/sbin\/sulogin/\/sbin\/sulogin/g' /usr/lib/systemd/system/rescue.service
sed -i 's/\/usr\/sbin\/sulogin/\/sbin\/sulogin/g' /usr/lib/systemd/system/emergency.service
mount -o remount,nodev,nosuid,noexec /dev/shm
echo "password  sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
echo "password  sufficient pam_unix.so remember=5" >> /etc/pam.d/password-auth
EOF
sed -i 's/\/usr\/sbin\/sulogin/\/sbin\/sulogin/g' /usr/lib/systemd/system/rescue.service
sed -i 's/\/usr\/sbin\/sulogin/\/sbin\/sulogin/g' /usr/lib/systemd/system/emergency.service
mount -o remount,nodev,nosuid,noexec /dev/shm
chmod +x /etc/rc.d/rc.local

### Create default config for NetworkManager
tee /etc/NetworkManager/NetworkManager.conf << EOF
# Configuration file for NetworkManager.
#
# See "man 5 NetworkManager.conf" for details.
#
# The directory /etc/NetworkManager/conf.d/ can contain additional configuration
# snippets. Those snippets override the settings from this main file.
#
# The files within conf.d/ directory are read in asciibetical order.
#
# If two files define the same key, the one that is read afterwards will overwrite
# the previous one.

[main]
plugins=ifcfg-rh
dns=none

[logging]
#level=DEBUG
#domains=ALL
EOF
#
### CIS
sed -i 's/\/usr\/sbin\/sulogin/\/sbin\/sulogin/g' /usr/lib/systemd/system/rescue.service
sed -i 's/\/usr\/sbin\/sulogin/\/sbin\/sulogin/g' /usr/lib/systemd/system/emergency.service
#
### CIS
sed -i 's/md5/sha512/g' /etc/pam.d/password-auth
sed -i 's/md5/sha512/g' /etc/pam.d/system-auth
sed -i 's/md5/sha512/g' /etc/pam.d/system-auth-ac
#
### CIS
chmod 600 /etc/gshadow-
#
sed -i 's/bind/bind,nodev,noexec,nosuid/g' /etc/fstab
#
### AIDE DB Setup
aide --init
### AIDE CRON
<< EOF cat > /etc/cron.d/aide
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
00 12 * * * root /usr/sbin/aide --check
EOF
#
# Setup Services
for A in network rhnsd
do
    chkconfig $A on --level 2345
done

echo "B"
for B in auditd crond iptables irqbalance lvm2-monitor microcode ntpdate ntpd postfix rhsmcertd rsyslog smartd sshd sysstat systemd-readahead-collect systemd-readahead-drop systemd-readahead-replay tuned dm-event lvm2-lvmetad rpcbind sshd
do
    chkconfig $B on
done

echo "C"
for C in arp-ethers autofs blk-availability certmonger cpupower debug-shell dm-event dnsmasq ebtables gssproxy kdump lldpad lvm2-lvmetad NetworkManager-dispatcher NetworkManager-wait-online nfs-server nmb nscd nslcd ras-mc-ctl rasdaemon rdisc rdma rhel-dmesg rhel-domainname rsyncd smb targetd tcsd wpa_supplicant lldpad nscd rsyncd graphical
do
    chkconfig $C off
done
#
# Disable Subscription Manager's management of YUM repositories
/usr/bin/subscription-manager config --rhsm.manage_repos=0
sed -i "s/enabled=1/enabled=0/g" /etc/yum/pluginconf.d/subscription-manager.conf
#
yum remove net-snmp net-snmp-agent-libs net-snmp-libs -y
#
# Cleanup
rm -f /var/log/anaconda.*

echo ”1.1.17 Ensure noexec option set on /dev/shm partition”
mount -o remount,noexec /dev/shm

echo “5.2.2 Ensure SSH Protocol is set to 2”
sed -i -e "s/#Protocol\\ 2/Protocol\\ 2/" /etc/ssh/sshd_config

echo “5.2.3 Ensure SSH LogLevel is set to INFO”
sed -i -e "s/#LogLevel\\ INFO/LogLevel\\ INFO/" /etc/ssh/sshd_config

echo “5.2.4 Ensure SSH X11 forwarding is disabled”
sed -i -e "s/X11Forwarding\\ yes/X11Forwarding\\ no/" /etc/ssh/sshd_config
service sshd reload

echo “5.2.5 Ensure SSH MaxAuthTries is set to 4 or less”
sed -i -e "s/#MaxAuthTries\\ 6/MaxAuthTries\\ 4/" /etc/ssh/sshd_config


echo “5.2.6 Ensure SSH IgnoreRhosts is enabled”
sed -i -e "s/#IgnoreRhosts/IgnoreRhosts/" /etc/ssh/sshd_config

echo "5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored)"
sed -i -e "s/#HostbasedAuthentication/HostbasedAuthentication/" /etc/ssh/sshd_config

echo "5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored)"
sed -i -e "s/#PermitEmptyPasswords/PermitEmptyPasswords/" /etc/ssh/sshd_config

echo "5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored)"
sed -i -e "s/#PermitUserEnvironment/PermitUserEnvironment/" /etc/ssh/sshd_config

echo “5.2.11 Ensure only approved ciphers are used”
sed -i -e "s/#\ Ciphers\\ and\\ keying/Ciphers\\ aes256-ctr,aes192-ctr,aes128-ctr/" /etc/ssh/sshd_config

echo “5.2.12 Ensure only approved MAC algorithms are used”
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config

echo “5.2.13 Ensure SSH Idle Timeout Interval is configured”
sed -i -e "s/#ClientAliveInterval\\ 0/ClientAliveInterval\\ 300/" /etc/ssh/sshd_config

sed -i -e "s/#ClientAliveCountMax\\ 3/ClientAliveCountMax\\ 3/" /etc/ssh/sshd_config

echo “5.2.14 Ensure SSH LoginGraceTime is set to one minute or less”
sed -i -e "s/#LoginGraceTime\\ 2m/LoginGraceTime\\ 60/" /etc/ssh/sshd_config

mount -o remount,nodev,nosuid,noexec /dev/shm
echo "#Check aide" >> /etc/cron.d/sandboxcron
echo "0 5 * * * /usr/sbin/aide --check" >> /etc/cron.d/sandboxcron
chmod og-rwx /boot/grub/menu.lst
echo "SELINUX=enforcing" >> /etc/selinux/config
echo "SELINUXTYPE=targeted" >> /etc/selinux/config
chmod 644 /etc/motd
yum remove xorg-x11* -y
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1iptables -L -v -n

echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >>  /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules

echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale"  >> /etc/audit/audit.rules
echo "-w /etc/issue -p wa -k system-locale"  >> /etc/audit/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale"  >> /etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k system-locale"  >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale"  >> /etc/audit/audit.rules

echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules

echo "-w /var/log/lastlog -p wa -k logins"  >> /etc/audit/audit.rules
echo "-w /var/run/faillock/ -p wa -k logins"  >> /etc/audit/audit.rules

echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules
echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules

echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access"  >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"  >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access"  >> /etc/audit/audit.rules


echo "a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules

echo "a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"  >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"  >> /etc/audit/audit.rules


echo "-w /etc/sudoers -p wa -k scope"  >> /etc/audit/audit.rules
echo "-w /etc/sudoers.d -p wa -k scope"  >> /etc/audit/audit.rules

echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules


echo "-w /sbin/insmod -p x -k modules"  >> /etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules"  >> /etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules"  >> /etc/audit/audit.rules
echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules"  >> /etc/audit/audit.rules


echo "-e 2" >> /etc/audit/audit.rules

chmod og-rwx /etc/cron.hourly
