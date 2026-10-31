#!/bin/bash
# PC1 (10.0.1.2) -- Device1 -- Device2 -- PC2 (10.0.3.2)
#   link A: PC1 <-> Dev1   10.0.1.0/24
#   link B: Dev1 <-> Dev2  10.0.2.0/24   (carries encrypted segments)
#   link C: Dev2 <-> PC2   10.0.3.0/24
set -e
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
SVC_PORT=5000

for ns in ns_pc1 ns_dev1 ns_dev2 ns_pc2; do ip netns add $ns; done

ip link add pc1-d1 type veth peer name d1-pc1
ip link add d1-d2  type veth peer name d2-d1
ip link add d2-pc2 type veth peer name pc2-d2

ip link set pc1-d1 netns ns_pc1
ip link set d1-pc1 netns ns_dev1
ip link set d1-d2  netns ns_dev1
ip link set d2-d1  netns ns_dev2
ip link set d2-pc2 netns ns_dev2
ip link set pc2-d2 netns ns_pc2

# cfg <ns> <dev> <cidr> <mtu>
cfg() { ip netns exec $1 ip addr add $3 dev $2
        ip netns exec $1 ip link set $2 mtu $4
        ip netns exec $1 ip link set $2 up
        ip netns exec $1 ip link set lo up; }

# MTU design (important): the hosts use MTU 1400, so they send segments of at most 1400 bytes.
# Encryption adds 24 bytes (16 tag + 8 counter), so a protected packet is up to 1424 bytes.
# The kernel checks a forwarded packet against the OUTGOING interface MTU *before* the
# NFQUEUE hook runs, so the device-side interfaces must be 1500 (not 1400), otherwise
# Device2 would drop full-size encrypted segments before it can decrypt them.
cfg ns_pc1  pc1-d1 10.0.1.2/24 1400
cfg ns_dev1 d1-pc1 10.0.1.1/24 1500
cfg ns_dev1 d1-d2  10.0.2.1/24 1500
cfg ns_dev2 d2-d1  10.0.2.2/24 1500
cfg ns_dev2 d2-pc2 10.0.3.1/24 1500
cfg ns_pc2  pc2-d2 10.0.3.2/24 1400

ip netns exec ns_pc1  ip route add default via 10.0.1.1
ip netns exec ns_pc2  ip route add default via 10.0.3.1
ip netns exec ns_dev1 ip route add 10.0.3.0/24 via 10.0.2.2
ip netns exec ns_dev2 ip route add 10.0.1.0/24 via 10.0.2.1
ip netns exec ns_dev1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns_dev2 sysctl -qw net.ipv4.ip_forward=1

# Disable offloads so the gateways see real MTU-sized packets with valid checksums
off() { ip netns exec $1 ethtool -K $2 tso off gso off gro off tx off rx off >/dev/null 2>&1 || true; }
off ns_pc1 pc1-d1; off ns_dev1 d1-pc1; off ns_dev1 d1-d2
off ns_dev2 d2-d1; off ns_dev2 d2-pc2; off ns_pc2 pc2-d2

# Selected traffic = forwarded TCP with port $SVC_PORT in either direction, on the two
# interfaces the gateway handles. NFQUEUE has no --queue-bypass, so with no gateway
# running (or before the handshake finishes) this traffic is DROPPED (fail-closed).
q() { ip netns exec $1 iptables -I FORWARD -i $2 -p tcp -m multiport --ports $SVC_PORT -j NFQUEUE --queue-num 0; }
q ns_dev1 d1-pc1; q ns_dev1 d1-d2
q ns_dev2 d2-pc2; q ns_dev2 d2-d1

echo "Testing plain connectivity (ICMP is not selected, so it passes unmodified)..."
ip netns exec ns_pc1 ping -c 2 -W 1 10.0.3.2
echo "Lab ready."