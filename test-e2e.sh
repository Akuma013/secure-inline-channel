#!/bin/bash
# End-to-end tests. Run from the folder containing ./secure_gw, after setup-secure-netns.sh:
#   sudo ./test-e2e.sh
# Needs: nc (netcat-openbsd), sha256sum. Starts/stops the gateways itself.
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
GW=./secure_gw
D=$(mktemp -d)
head -c 32 /dev/urandom | base64 > $D/psk.good; chmod 600 $D/psk.good
head -c 32 /dev/urandom | base64 > $D/psk.bad;  chmod 600 $D/psk.bad
pass=0; fail=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }

start_gws() {   # $1 = psk for dev2, $2 = psk for dev1, $3.. = extra dev1 flags
  local p2=$1 p1=$2; shift 2
  ip netns exec ns_dev2 $GW --role responder --inside d2-pc2 --peer-if d2-d1 \
      --local 10.0.2.2 --peer 10.0.2.1 --psk-file $p2 > $D/gw2.log 2>&1 & G2=$!
  ip netns exec ns_dev1 $GW --role initiator --inside d1-pc1 --peer-if d1-d2 \
      --local 10.0.2.1 --peer 10.0.2.2 --psk-file $p1 "$@" > $D/gw1.log 2>&1 & G1=$!
}
stop_gws() { kill $G1 $G2 2>/dev/null; wait $G1 $G2 2>/dev/null; G1=; G2=; }
wait_ready() { for i in $(seq 1 15); do
    grep -q "gateway running" $D/gw1.log && grep -q "gateway running" $D/gw2.log && return 0; sleep 1; done; return 1; }

transfer() {    # sends $D/in.bin from PC1 to PC2, result in $D/out.bin
  rm -f $D/out.bin
  ip netns exec ns_pc2 sh -c "timeout 12 nc -l 10.0.3.2 5000 > $D/out.bin" & local R=$!
  sleep 1
  ip netns exec ns_pc1 timeout 8 nc -N 10.0.3.2 5000 < $D/in.bin >/dev/null 2>&1
  sleep 1; kill $R 2>/dev/null; wait $R 2>/dev/null
}
head -c 2M /dev/urandom > $D/in.bin

echo "== T1: normal operation (matching PSK), 2 MB transfer =="
start_gws $D/psk.good $D/psk.good
if wait_ready; then ok "handshake completed"; else bad "handshake did not complete"; fi
transfer
if cmp -s $D/in.bin $D/out.bin; then ok "file arrives intact (hashes equal)"; else bad "file corrupted or missing"; fi
stop_gws
grep -q "stats: encrypted=[1-9]" $D/gw1.log && ok "Device1 encrypted packets" || bad "Device1 encrypted nothing"
grep -q "stats: .*decrypted=[1-9]" $D/gw2.log && ok "Device2 decrypted packets" || bad "Device2 decrypted nothing"

echo "== T2: tampering is detected =="
start_gws $D/psk.good $D/psk.good --tamper
wait_ready
transfer
stop_gws
[ ! -s $D/out.bin ] && ok "PC2 received nothing" || bad "PC2 received data despite tampering"
grep -q "authentication failed" $D/gw2.log && ok "Device2 logged authentication failure" || bad "no auth failure logged"

echo "== T3: wrong PSK => no session, no data =="
start_gws $D/psk.bad $D/psk.good
sleep 6
grep -q "gateway running" $D/gw1.log && bad "gateway started with mismatched PSK" || ok "handshake refused (PSK mismatch)"
transfer
stop_gws
[ ! -s $D/out.bin ] && ok "no data passed without a valid session" || bad "data leaked without a session"

echo "== T4: gateways down => selected traffic blocked (fail-closed) =="
transfer
[ ! -s $D/out.bin ] && ok "traffic blocked" || bad "traffic passed without gateways"

echo; echo "Results: $pass passed, $fail failed   (logs in $D)"
[ $fail -eq 0 ]
