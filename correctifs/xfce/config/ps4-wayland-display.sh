#!/bin/sh
sleep 3
/usr/bin/wlr-randr --output HDMI-A-1 --mode 1920x1080@60Hz
sleep 1
exec /usr/bin/swaybg -i /usr/share/backgrounds/xfce/xfce-blue.jpg -m fill
