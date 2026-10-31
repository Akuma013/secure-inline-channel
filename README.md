# Secure Inline Channel (DH + AES-GCM on the TCP payload)

A Linux prototype of a secure inline channel between two hosts:

```
PC1 ──► Device1 ═══════════════► Device2 ──► PC2
        (encrypt)  encrypted TCP   (verify, decrypt,
                   payloads        fix checksums)
```

Device1 and Device2 are transparent IP routers. They intercept selected TCP/IPv4 traffic
(TCP port 5000 by default), establish a secure session with an authenticated
Diffie–Hellman handshake, and then protect every packet between them. The two PCs run
ordinary, unmodified, plaintext software and never know the channel exists.

Everything runs on one Linux machine using network namespaces (PC1, Device1, Device2, PC2).

## How it works

1. **Handshake.** Device1 (initiator) and Device2 (responder) run a finite-field
   Diffie–Hellman exchange (RFC 7919 group `ffdhe2048`) over a separate control
   connection (TCP port 6000). Both DH messages are authenticated with an HMAC-SHA256 keyed
   with a pre-shared key, so a man-in-the-middle cannot substitute DH values. After the keys
   are derived, both devices exchange a key-confirmation MAC. Session keys are installed
   only if everything verifies.
2. **Key derivation.** HKDF-SHA256 turns the DH secret into **two independent AES-256 keys,
   one per direction**, plus a confirmation key. The PSK and both DH public values are mixed
   into the salt.
3. **Encrypt (device next to the sender).** For every selected TCP packet, only the TCP
   payload is encrypted with AES-256-GCM. The IP and TCP headers are kept. The 16-byte
   authentication tag is appended to the ciphertext, followed by an 8-byte packet counter.
   The packet is forwarded to the peer device **as ordinary routed IP, with no UDP
   encapsulation and no custom protocol header**.
4. **Verify and decrypt (device next to the receiver).** The tag is verified; on failure
   the packet is dropped. Otherwise the payload is decrypted, the original packet is
   restored, the IP length and the IP and TCP checksums are recomputed, and the packet is
   forwarded to the destination host.

Traffic is blocked until the handshake completes: the `iptables` NFQUEUE rules have no
reader until the gateway has an established session, so the kernel drops selected packets
(fail-closed).

## Packet format

```
Between PC and device:   | IP header | TCP header | plaintext payload |
Between the devices:     | IP header | TCP header | ciphertext | tag (16) | counter (8) |
```

The IP and TCP headers are unchanged except for the IP total length and the checksums,
which are recalculated. TCP sequence and acknowledgment numbers are **not** rewritten, so
on the device-to-device link a segment is 24 bytes longer than its sequence numbers
suggest. Packet analyzers may flag this. After decryption, the hosts see the original
sizes.

Every segment of a selected flow is protected, including SYN, ACK, FIN and RST (they
carry only tag + counter), so forged control packets cannot be injected between the devices.

## Nonce strategy

- AES-GCM nonce (12 bytes) = 4 zero bytes + 64-bit packet counter.
- The counter starts at 0 for each session, increments for every packet, and is never reused
  or reset. TCP retransmissions get a fresh counter.
- Each direction has its own key, so the two directions can never produce the same
  (key, nonce) pair.
- The 8-byte counter is carried after the tag so the receiver can rebuild the nonce.
- After 2^32 packets the gateway stops forwarding (fail-closed) instead of reusing a nonce.

## What is authenticated

The GCM additional authenticated data contains the source IP, destination IP, IP protocol,
and the **entire TCP header** (ports, sequence, acknowledgment, flags, window, options)
with the checksum zeroed. Changing any of these fields on the wire makes verification fail.
The IP TTL, DSCP/ECN and ID fields change legitimately in transit and are not covered.

## Replay protection

The receiver keeps a 1024-packet sliding window of counters. Replayed or too-old
counters are dropped. A counter is recorded only after the packet authenticates.
Reordering within the window is tolerated.

## Files

| File | Purpose |
|---|---|
| `secure_gw.c` | The gateway, run on both Device1 and Device2. Includes `--selftest`. |
| `setup-secure-netns.sh` | Builds the four-namespace lab and the `iptables` rules. |
| `teardown-secure-netns.sh` | Removes the lab. |
| `test-e2e.sh` | End-to-end tests (transfer, tamper, wrong PSK, no gateway). |
| `pc_apps.c` | Optional plaintext test client/server for PC1/PC2 (`nc` works too). |

## Requirements

Linux with network namespaces (tested on Linux Mint), root access, and:

```bash
sudo apt install build-essential libssl-dev libnetfilter-queue-dev iptables iproute2 ethtool tcpdump netcat-openbsd
```

OpenSSL 3.0 or newer is required.

## Build

```bash
gcc -O2 -Wall -Wextra -o secure_gw secure_gw.c -lnetfilter_queue -lssl -lcrypto
gcc -o pc_apps pc_apps.c            # optional
```

## Run

Create a pre-shared key (both devices use the same file; keep it private, mode 0600):

```bash
head -c 32 /dev/urandom | base64 > psk.key && chmod 600 psk.key
```

Build the lab. (The scripts are run with `bash` so they work even if the executable bit was
lost on download; alternatively run `chmod +x *.sh` once and then use `sudo ./script.sh`.)

```bash
sudo bash ./setup-secure-netns.sh
```

Start the gateways, responder first (one terminal each; add `-v` for per-packet logs):

```bash
# Device2
sudo ip netns exec ns_dev2 ./secure_gw --role responder --inside d2-pc2 --peer-if d2-d1 \
     --local 10.0.2.2 --peer 10.0.2.1 --psk-file psk.key

# Device1
sudo ip netns exec ns_dev1 ./secure_gw --role initiator --inside d1-pc1 --peer-if d1-d2 \
     --local 10.0.2.1 --peer 10.0.2.2 --psk-file psk.key
```

Send traffic from PC1 to PC2:

```bash
sudo ip netns exec ns_pc2 nc -l 10.0.3.2 5000
echo "hello secure world" | sudo ip netns exec ns_pc1 nc -N 10.0.3.2 5000
```

Watch the wire (ciphertext between devices, plaintext on the host side):

```bash
sudo ip netns exec ns_dev1 tcpdump -i d1-d2  -X -n 'tcp port 5000'   # encrypted
sudo ip netns exec ns_dev1 tcpdump -i d1-pc1 -X -n 'tcp port 5000'   # plaintext
```

Remove the lab when done: `sudo bash ./teardown-secure-netns.sh`.

## Tests

```bash
./secure_gw --selftest        # 43 checks, no root needed
sudo bash ./test-e2e.sh       # needs the lab (run setup first); starts the gateways itself
```

When the self-test output is redirected to a file, two stderr lines (`[drop] replayed or too-old
counter 0` and `initiator failed authentication`) can appear at the top. They are expected: they
are the messages produced by the replay test and the deliberate wrong-PSK handshake test.

The self-test covers: round trip, header preservation, checksums, replay rejection,
tampering with the ciphertext, tag, counter and every header field, wrong key,
protection of empty segments, 100,000 unique increasing counters, reordering, the replay
window limit, policy checks, and the authenticated handshake (including a wrong-PSK run).

The end-to-end test checks a 2 MB transfer with identical hashes, tampering detection,
rejection of a wrong PSK, and blocked traffic when no gateway is running.

## MTU design

The hosts use MTU 1400 and the device-side interfaces use MTU 1500. Encryption adds 24 bytes,
so a full-size 1400-byte segment becomes 1424 bytes. The Linux kernel compares a forwarded
packet against the **outgoing** interface MTU *before* the NFQUEUE hook runs, so the
device-side interfaces must be large enough to accept the encrypted packet. With 1400 on
those interfaces, Device2 silently dropped full-size encrypted segments and bulk transfers
stalled.

## Limitations

- Prototype: IPv4 and TCP only, one selected port, no IP fragments.
- **No rekeying.** One handshake protects the whole session. A hard limit of 2^32 packets
  stops forwarding; restart the gateways to establish a new session.
- A single pre-shared key authenticates both devices. If it leaks, an attacker can
  impersonate a device. Certificates or signatures would be the next step.
- IP TTL, DSCP/ECN and ID are not authenticated.
- User-space processing through NFQUEUE is much slower than in-kernel encryption.
- TCP sequence numbers are not rewritten (see the packet format note above).
- Do not run this on a machine whose network matters without understanding the `iptables`
  rules: the NFQUEUE rules drop selected traffic whenever no gateway is running.
