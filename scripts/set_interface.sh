#!/bin/sudo /bin/sh

IP=192.168.1.100

if [ -z "$1" ];  then
    echo "Usage: $0 [interface_name] [ip (default $IP)]"
    exit 1
fi

if [ "$2" ]; then
    IP=$2
fi

echo "Setting interface $1, ip $IP.."

# Seth eth0 interface
modprobe dummy && \
ip link add $1 type dummy && \
ip addr add $IP/24 brd + dev $1 && \
sysctl -w net.ipv6.conf.$1.disable_ipv6=1 && \
ifconfig $1 multicast && \
ip link set dev $1 up && \
route add -net 239.0.0.0 netmask 255.0.0.0 $1 && \
ifconfig eth0

