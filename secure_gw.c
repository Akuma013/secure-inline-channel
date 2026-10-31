/*
 * secure_gw.c (v2) - inline secure channel gateway (runs on Device1 and Device2)
 *
 *   PC1 -> Device1 ==(TCP payloads encrypted with AES-256-GCM)==> Device2 -> PC2
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o secure_gw secure_gw.c -lnetfilter_queue -lssl -lcrypto
 *
 * Run (inside the device's network namespace, as root):
 *   secure_gw --role initiator|responder --inside IF --peer-if IF \
 *             --local IP --peer IP --psk-file FILE [--port 5000] [--ctrl-port 6000]
 *             [--queue 0] [-v]
 *   secure_gw --selftest        (no root needed; tests crypto/packet/handshake logic)
 *
 * Security properties
 *  - DH (ffdhe2048) handshake, authenticated with a pre-shared key (HMAC-SHA256 over
 *    both DH values), plus explicit key confirmation. Defeats man-in-the-middle on the
 *    control channel and guarantees both devices hold identical keys before any data flows.
 *  - HKDF-SHA256 -> separate AES-256 key per direction; PSK is also mixed into the HKDF salt.
 *  - Every packet of a selected flow (including SYN/ACK/FIN/RST) is protected:
 *        TCP payload' = ciphertext || GCM tag (16) || counter (8)
 *    so unauthenticated segments (e.g. injected RSTs) never reach the other host.
 *  - AAD = src/dst IP, IP protocol and the ENTIRE TCP header (checksum excluded), so
 *    ports, seq, ack, flags, window and options are all authenticated.
 *  - Nonce = 4 zero bytes || 64-bit counter; counter is never reused (key is per direction).
 *  - 1024-packet sliding anti-replay window (tolerates reordering).
 *  - Fail-closed: no queue listener => kernel drops selected traffic; unknown ingress,
 *    fragments, malformed packets and failed authentication are all dropped.
 */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#define DH_GROUP     "ffdhe2048"
#define DH_PUB_LEN   256
#define KEY_LEN      32
#define NONCE_LEN    12
#define TAG_LEN      16
#define CTR_LEN      8
#define MAC_LEN      32
#define MAGIC        "SGW2"
#define MAGIC_LEN    4
#define HELLO_LEN    (MAGIC_LEN + DH_PUB_LEN + MAC_LEN)
#define MAX_AAD      (9 + 60)
#define MAXPKT       65535
#define RW_BITS      1024
#define PKT_LIMIT    (1ULL << 32)   /* hard per-session packet limit; then fail closed */
#define IO_TIMEOUT_S 5

/* ---------------------------------------------------------------- state */
static uint8_t  tx_key[KEY_LEN], rx_key[KEY_LEN];
static uint64_t tx_ctr;
static struct { int init; uint64_t max; uint64_t bits[RW_BITS / 64]; } rw;
static unsigned inside_idx, peer_idx;
static int svc_port = 5000, ctrl_port = 6000, queue_num = 0, verbose = 0, tamper = 0;
static volatile sig_atomic_t stop_flag;
static struct { uint64_t enc, dec, drop_auth, drop_replay, drop_other, enobufs; } st;

#define DROP(f) do { st.f++; return -1; } while (0)

static void die(const char *m) { fprintf(stderr, "fatal: %s\n", m); exit(1); }

/* at most one message per second, with a count of suppressed ones */
static void warn_limited(const char *fmt, ...) {
    static time_t last; static unsigned suppressed;
    time_t now = time(NULL);
    if (now == last) { suppressed++; return; }
    if (suppressed) { fprintf(stderr, "(%u similar messages suppressed)\n", suppressed); suppressed = 0; }
    last = now;
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

/* ---------------------------------------------------------------- HMAC helper */
/* out = HMAC-SHA256(key, label || a || b) */
static int hmac3(const uint8_t *key, size_t klen, const char *label,
                 const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                 uint8_t out[MAC_LEN]) {
    uint8_t buf[8 + 2 * DH_PUB_LEN];
    size_t ll = strlen(label);
    if (ll + alen + blen > sizeof buf) return 0;
    memcpy(buf, label, ll);
    memcpy(buf + ll, a, alen);
    if (blen) memcpy(buf + ll + alen, b, blen);
    unsigned int ol = 0;
    return HMAC(EVP_sha256(), key, (int)klen, buf, ll + alen + blen, out, &ol) != NULL && ol == MAC_LEN;
}

/* ------------------------------------------------------- DH + HKDF (OpenSSL 3) */
static EVP_PKEY *dh_keygen(void) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    OSSL_PARAM p[2] = { OSSL_PARAM_construct_utf8_string("group", (char *)DH_GROUP, 0),
                        OSSL_PARAM_construct_end() };
    EVP_PKEY *k = NULL;
    if (!c || EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_CTX_set_params(c, p) <= 0 ||
        EVP_PKEY_keygen(c, &k) <= 0) die("DH keygen");
    EVP_PKEY_CTX_free(c);
    return k;
}

static void dh_pub(EVP_PKEY *k, uint8_t out[DH_PUB_LEN]) {
    BIGNUM *bn = NULL;
    if (!EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_PUB_KEY, &bn)) die("DH pub export");
    if (BN_bn2binpad(bn, out, DH_PUB_LEN) != DH_PUB_LEN) die("DH pub size");
    BN_free(bn);
}

/* imports AND validates the peer's public value; NULL if invalid */
static EVP_PKEY *dh_peer(const uint8_t pub[DH_PUB_LEN]) {
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *c = NULL, *chk = NULL;
    OSSL_PARAM_BLD *b = NULL;
    OSSL_PARAM *prm = NULL;
    BIGNUM *bn = BN_bin2bn(pub, DH_PUB_LEN, NULL);
    int ok = 0;
    if (!bn) return NULL;
    b = OSSL_PARAM_BLD_new();
    if (b && OSSL_PARAM_BLD_push_utf8_string(b, "group", DH_GROUP, 0) &&
        OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PUB_KEY, bn) &&
        (prm = OSSL_PARAM_BLD_to_param(b)) &&
        (c = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)) &&
        EVP_PKEY_fromdata_init(c) > 0 &&
        EVP_PKEY_fromdata(c, &pk, EVP_PKEY_PUBLIC_KEY, prm) > 0 &&
        (chk = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL)) &&
        EVP_PKEY_public_check(chk) > 0) ok = 1;
    EVP_PKEY_CTX_free(chk); EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(prm); OSSL_PARAM_BLD_free(b); BN_free(bn);
    if (!ok) { EVP_PKEY_free(pk); pk = NULL; }
    return pk;
}

/* DH secret -> tx/rx/confirmation keys. 0 on success. */
static int derive_session(EVP_PKEY *mine, const uint8_t *A, const uint8_t *B,
                          const uint8_t *their_pub, const uint8_t *psk, size_t pl,
                          int initiator, uint8_t tx[KEY_LEN], uint8_t rx[KEY_LEN],
                          uint8_t ck[KEY_LEN]) {
    uint8_t transcript[2 * DH_PUB_LEN], salt[MAC_LEN], secret[DH_PUB_LEN], okm[3 * KEY_LEN];
    size_t n = 0, olen = sizeof okm;
    int rc = -1;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *d = NULL, *h = NULL;

    memcpy(transcript, A, DH_PUB_LEN);
    memcpy(transcript + DH_PUB_LEN, B, DH_PUB_LEN);

    peer = dh_peer(their_pub);
    if (!peer) { fprintf(stderr, "invalid DH public value from peer\n"); goto out; }

    d = EVP_PKEY_CTX_new_from_pkey(NULL, mine, NULL);
    if (!d || EVP_PKEY_derive_init(d) <= 0 || EVP_PKEY_derive_set_peer(d, peer) <= 0 ||
        EVP_PKEY_derive(d, NULL, &n) <= 0 || n > sizeof secret ||
        EVP_PKEY_derive(d, secret, &n) <= 0) goto out;

    /* salt = HMAC(psk, transcript): binds the PSK and both DH values into the keys */
    if (!hmac3(psk, pl, "salt", transcript, sizeof transcript, NULL, 0, salt)) goto out;

    h = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!h || EVP_PKEY_derive_init(h) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(h, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(h, salt, sizeof salt) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(h, secret, (int)n) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(h, (const unsigned char *)"secure-gw v2", 12) <= 0 ||
        EVP_PKEY_derive(h, okm, &olen) <= 0) goto out;

    /* okm: [0,32) initiator->responder  [32,64) responder->initiator  [64,96) confirm */
    memcpy(tx, initiator ? okm : okm + KEY_LEN, KEY_LEN);
    memcpy(rx, initiator ? okm + KEY_LEN : okm, KEY_LEN);
    memcpy(ck, okm + 2 * KEY_LEN, KEY_LEN);
    rc = 0;
out:
    EVP_PKEY_free(peer); EVP_PKEY_CTX_free(d); EVP_PKEY_CTX_free(h);
    OPENSSL_cleanse(secret, sizeof secret); OPENSSL_cleanse(okm, sizeof okm);
    return rc;
}

/* ---------------------------------------------------------------- handshake I/O */
static int io_full(int fd, void *buf, size_t n, int do_write) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = do_write ? send(fd, p, n, MSG_NOSIGNAL) : recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR && !stop_flag) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

/*  I -> R : MAGIC | A | HMAC(psk,"I"|A)
 *  R -> I : MAGIC | B | HMAC(psk,"R"|A|B)
 *  I -> R : HMAC(ck,"CI"|A|B)       (key confirmation)
 *  R -> I : HMAC(ck,"CR"|A|B)
 * Session keys are installed only after both confirmations verify. */
static int hs_initiator(int fd, const uint8_t *psk, size_t pl) {
    int rc = -1;
    EVP_PKEY *mine = dh_keygen();
    uint8_t A[DH_PUB_LEN], m1[HELLO_LEN], m2[HELLO_LEN], mac[MAC_LEN], exp[MAC_LEN], rmac[MAC_LEN];
    uint8_t ck[KEY_LEN], tx[KEY_LEN], rx[KEY_LEN];
    const uint8_t *B = m2 + MAGIC_LEN;

    dh_pub(mine, A);
    memcpy(m1, MAGIC, MAGIC_LEN);
    memcpy(m1 + MAGIC_LEN, A, DH_PUB_LEN);
    if (!hmac3(psk, pl, "I", A, DH_PUB_LEN, NULL, 0, m1 + MAGIC_LEN + DH_PUB_LEN)) goto out;
    if (io_full(fd, m1, sizeof m1, 1) || io_full(fd, m2, sizeof m2, 0)) goto out;
    if (memcmp(m2, MAGIC, MAGIC_LEN)) goto out;
    if (!hmac3(psk, pl, "R", A, DH_PUB_LEN, B, DH_PUB_LEN, exp) ||
        CRYPTO_memcmp(exp, B + DH_PUB_LEN, MAC_LEN)) {
        fprintf(stderr, "responder failed authentication (PSK mismatch?)\n"); goto out;
    }
    if (derive_session(mine, A, B, B, psk, pl, 1, tx, rx, ck)) goto out;
    if (!hmac3(ck, KEY_LEN, "CI", A, DH_PUB_LEN, B, DH_PUB_LEN, mac) || io_full(fd, mac, MAC_LEN, 1)) goto out;
    if (io_full(fd, rmac, MAC_LEN, 0)) goto out;
    if (!hmac3(ck, KEY_LEN, "CR", A, DH_PUB_LEN, B, DH_PUB_LEN, exp) ||
        CRYPTO_memcmp(exp, rmac, MAC_LEN)) { fprintf(stderr, "key confirmation failed\n"); goto out; }
    memcpy(tx_key, tx, KEY_LEN); memcpy(rx_key, rx, KEY_LEN);
    rc = 0;
out:
    EVP_PKEY_free(mine);
    OPENSSL_cleanse(tx, KEY_LEN); OPENSSL_cleanse(rx, KEY_LEN); OPENSSL_cleanse(ck, KEY_LEN);
    return rc;
}

static int hs_responder(int fd, const uint8_t *psk, size_t pl) {
    int rc = -1;
    EVP_PKEY *mine = NULL;
    uint8_t m1[HELLO_LEN], m2[HELLO_LEN], B[DH_PUB_LEN], mac[MAC_LEN], exp[MAC_LEN], cmac[MAC_LEN];
    uint8_t ck[KEY_LEN], tx[KEY_LEN], rx[KEY_LEN];
    const uint8_t *A = m1 + MAGIC_LEN;

    if (io_full(fd, m1, sizeof m1, 0) || memcmp(m1, MAGIC, MAGIC_LEN)) goto out;
    /* authenticate BEFORE doing any expensive DH work */
    if (!hmac3(psk, pl, "I", A, DH_PUB_LEN, NULL, 0, exp) ||
        CRYPTO_memcmp(exp, A + DH_PUB_LEN, MAC_LEN)) {
        fprintf(stderr, "initiator failed authentication (PSK mismatch?)\n"); goto out;
    }
    mine = dh_keygen();
    dh_pub(mine, B);
    memcpy(m2, MAGIC, MAGIC_LEN);
    memcpy(m2 + MAGIC_LEN, B, DH_PUB_LEN);
    if (!hmac3(psk, pl, "R", A, DH_PUB_LEN, B, DH_PUB_LEN, m2 + MAGIC_LEN + DH_PUB_LEN)) goto out;
    if (io_full(fd, m2, sizeof m2, 1)) goto out;
    if (derive_session(mine, A, B, A, psk, pl, 0, tx, rx, ck)) goto out;
    if (io_full(fd, cmac, MAC_LEN, 0)) goto out;
    if (!hmac3(ck, KEY_LEN, "CI", A, DH_PUB_LEN, B, DH_PUB_LEN, exp) ||
        CRYPTO_memcmp(exp, cmac, MAC_LEN)) { fprintf(stderr, "key confirmation failed\n"); goto out; }
    if (!hmac3(ck, KEY_LEN, "CR", A, DH_PUB_LEN, B, DH_PUB_LEN, mac) || io_full(fd, mac, MAC_LEN, 1)) goto out;
    memcpy(tx_key, tx, KEY_LEN); memcpy(rx_key, rx, KEY_LEN);
    rc = 0;
out:
    EVP_PKEY_free(mine);
    OPENSSL_cleanse(tx, KEY_LEN); OPENSSL_cleanse(rx, KEY_LEN); OPENSSL_cleanse(ck, KEY_LEN);
    return rc;
}

static void set_timeouts(int fd) {
    struct timeval tv = { IO_TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static void establish_session(int initiator, const char *local, const char *peer,
                              const uint8_t *psk, size_t pl) {
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)ctrl_port);

    if (initiator) {
        inet_pton(AF_INET, peer, &a.sin_addr);
        while (!stop_flag) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
                close(fd);
                fprintf(stderr, "waiting for responder %s:%d ...\n", peer, ctrl_port);
                sleep(1); continue;
            }
            set_timeouts(fd);
            int rc = hs_initiator(fd, psk, pl);
            close(fd);
            if (rc == 0) return;
            fprintf(stderr, "handshake failed; retrying in 2s\n");
            sleep(2);
        }
    } else {
        inet_pton(AF_INET, local, &a.sin_addr);
        int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 4) < 0) die("ctrl bind/listen");
        fprintf(stderr, "waiting for initiator on %s:%d ...\n", local, ctrl_port);
        char want[INET_ADDRSTRLEN]; snprintf(want, sizeof want, "%s", peer);
        while (!stop_flag) {
            struct sockaddr_in c; socklen_t cl = sizeof c;
            int fd = accept(ls, (struct sockaddr *)&c, &cl);
            if (fd < 0) { if (errno == EINTR) continue; die("accept"); }
            char got[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &c.sin_addr, got, sizeof got);
            if (strcmp(got, want) != 0) { fprintf(stderr, "ignoring control connection from %s\n", got); close(fd); continue; }
            set_timeouts(fd);
            int rc = hs_responder(fd, psk, pl);
            close(fd);
            if (rc == 0) { close(ls); return; }
            fprintf(stderr, "handshake failed; still waiting\n");   /* stray/bad peer must not kill us */
        }
    }
    exit(0);   /* interrupted */
}

/* ------------------------------------------------------------- AES-256-GCM */
static void make_nonce(uint8_t n[NONCE_LEN], uint64_t c) {
    memset(n, 0, 4);
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(c >> (56 - 8 * i));
}

/* AAD = saddr | daddr | protocol | full TCP header with checksum zeroed */
static int build_aad(const uint8_t *in, int ihl, int thl, uint8_t *aad) {
    memcpy(aad, in + 12, 8);
    aad[8] = in[9];
    memcpy(aad + 9, in + ihl, (size_t)thl);
    aad[9 + 16] = aad[9 + 17] = 0;
    return 9 + thl;
}

static int gcm_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, int aadlen,
                       const uint8_t *in, int len, uint8_t *out, uint8_t *tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ok = c != NULL;
    if (!ok) return 0;
    ok &= EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    ok &= EVP_EncryptInit_ex(c, NULL, NULL, key, nonce);
    ok &= EVP_EncryptUpdate(c, NULL, &l, aad, aadlen);
    if (len > 0) ok &= EVP_EncryptUpdate(c, out, &l, in, len);
    ok &= EVP_EncryptFinal_ex(c, out + len, &l);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static int gcm_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, int aadlen,
                       const uint8_t *in, int len, const uint8_t *tag, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, ok = c != NULL;
    if (!ok) return 0;
    ok &= EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    ok &= EVP_DecryptInit_ex(c, NULL, NULL, key, nonce);
    ok &= EVP_DecryptUpdate(c, NULL, &l, aad, aadlen);
    if (len > 0) ok &= EVP_DecryptUpdate(c, out, &l, in, len);
    ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag);
    ok &= (EVP_DecryptFinal_ex(c, out + len, &l) > 0);      /* verifies the tag */
    EVP_CIPHER_CTX_free(c);
    return ok;
}

/* ------------------------------------------------- anti-replay window (1024) */
static int rw_get(uint64_t c) { unsigned i = (unsigned)(c % RW_BITS); return (rw.bits[i / 64] >> (i % 64)) & 1; }
static void rw_set(uint64_t c) { unsigned i = (unsigned)(c % RW_BITS); rw.bits[i / 64] |= 1ULL << (i % 64); }
static void rw_clr(uint64_t c) { unsigned i = (unsigned)(c % RW_BITS); rw.bits[i / 64] &= ~(1ULL << (i % 64)); }

static int replay_ok(uint64_t c) {                 /* 1 = fresh, 0 = replayed or too old */
    if (!rw.init || c > rw.max) return 1;
    if (rw.max - c >= RW_BITS) return 0;
    return !rw_get(c);
}
static void replay_update(uint64_t c) {            /* call only after successful authentication */
    if (!rw.init) { memset(&rw, 0, sizeof rw); rw.init = 1; rw.max = c; rw_set(c); return; }
    if (c > rw.max) {
        uint64_t s = c - rw.max;
        if (s >= RW_BITS) memset(rw.bits, 0, sizeof rw.bits);
        else for (uint64_t k = 1; k <= s; k++) rw_clr(rw.max + k);
        rw.max = c;
    }
    rw_set(c);
}

/* -------------------------------------------------------------- checksums */
static uint32_t sum16(const void *d, size_t n, uint32_t s) {
    const uint8_t *p = d;
    while (n > 1) { s += (uint32_t)((p[0] << 8) | p[1]); p += 2; n -= 2; }
    if (n) s += (uint32_t)(p[0] << 8);
    return s;
}
static uint16_t fold(uint32_t s) { while (s >> 16) s = (s & 0xffff) + (s >> 16); return htons((uint16_t)(~s & 0xffff)); }

static void fix_checksums(uint8_t *pkt) {
    struct iphdr *ip = (struct iphdr *)pkt;
    int ihl = ip->ihl * 4, tot = ntohs(ip->tot_len), tl = tot - ihl;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ihl);
    ip->check = 0;
    ip->check = fold(sum16(ip, (size_t)ihl, 0));
    tcp->check = 0;
    uint32_t s = sum16(&ip->saddr, 4, 0);
    s = sum16(&ip->daddr, 4, s);
    s += IPPROTO_TCP; s += (uint32_t)tl;
    tcp->check = fold(sum16(tcp, (size_t)tl, s));
}

/* ------------------------------------------------------------ packet logic */
/* returns: >0 new packet length in out[] ; 0 accept unchanged ; <0 drop */
static int process(const uint8_t *in, int len, uint32_t indev, uint8_t *out) {
    if (len < (int)sizeof(struct iphdr)) DROP(drop_other);
    const struct iphdr *ip = (const struct iphdr *)in;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return 0;

    int ihl = ip->ihl * 4;
    if (ihl < 20 || len < ihl + 20) DROP(drop_other);
    if (ntohs(ip->frag_off) & 0x3fff) DROP(drop_other);        /* fragments can't be protected */
    int tot = ntohs(ip->tot_len);
    if (tot > len || tot < ihl + 20) DROP(drop_other);

    const struct tcphdr *tcp = (const struct tcphdr *)(in + ihl);
    int thl = tcp->doff * 4;
    if (thl < 20 || ihl + thl > tot) DROP(drop_other);

    if (ntohs(tcp->source) != svc_port && ntohs(tcp->dest) != svc_port) return 0;   /* not selected */

    int hdr = ihl + thl, pl = tot - hdr;
    uint8_t aad[MAX_AAD], nonce[NONCE_LEN];
    int aadlen = build_aad(in, ihl, thl, aad);

    if (indev == inside_idx) {                                  /* ---- ENCRYPT (every segment) ---- */
        int newtot = tot + TAG_LEN + CTR_LEN;
        if (newtot > MAXPKT) DROP(drop_other);
        if (tx_ctr >= PKT_LIMIT) {
            warn_limited("[drop] session packet limit reached: restart the gateways to re-key");
            DROP(drop_other);
        }
        uint64_t c = tx_ctr++;                                  /* each counter value used once */
        make_nonce(nonce, c);
        memcpy(out, in, (size_t)hdr);
        if (!gcm_encrypt(tx_key, nonce, aad, aadlen, in + hdr, pl, out + hdr, out + hdr + pl)) DROP(drop_other);
        if (tamper) out[hdr + pl] ^= 1;                         /* demo/test only */
        for (int i = 0; i < 8; i++) out[hdr + pl + TAG_LEN + i] = (uint8_t)(c >> (56 - 8 * i));
        ((struct iphdr *)out)->tot_len = htons((uint16_t)newtot);
        fix_checksums(out);
        st.enc++;
        if (verbose) fprintf(stderr, "[enc] ctr=%llu payload %d -> %d\n", (unsigned long long)c, pl, pl + TAG_LEN + CTR_LEN);
        return newtot;
    }

    if (indev == peer_idx) {                                    /* ---- DECRYPT ---- */
        if (pl < TAG_LEN + CTR_LEN) DROP(drop_other);           /* unprotected segment: reject */
        int ct = pl - TAG_LEN - CTR_LEN;
        const uint8_t *tag = in + hdr + ct, *cp = tag + TAG_LEN;
        uint64_t c = 0;
        for (int i = 0; i < 8; i++) c = (c << 8) | cp[i];
        if (!replay_ok(c)) {
            warn_limited("[drop] replayed or too-old counter %llu", (unsigned long long)c);
            DROP(drop_replay);
        }
        make_nonce(nonce, c);
        memcpy(out, in, (size_t)hdr);
        if (!gcm_decrypt(rx_key, nonce, aad, aadlen, in + hdr, ct, tag, out + hdr)) {
            warn_limited("[drop] authentication failed (ctr=%llu)", (unsigned long long)c);
            DROP(drop_auth);
        }
        replay_update(c);
        int newtot = hdr + ct;
        ((struct iphdr *)out)->tot_len = htons((uint16_t)newtot);
        fix_checksums(out);
        st.dec++;
        if (verbose) fprintf(stderr, "[dec] ctr=%llu payload %d -> %d\n", (unsigned long long)c, pl, ct);
        return newtot;
    }
    DROP(drop_other);                                           /* unknown ingress: fail closed */
}

static uint8_t outbuf[MAXPKT + 64];

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *m, struct nfq_data *nfa, void *d) {
    (void)m; (void)d;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return 0;
    uint32_t id = ntohl(ph->packet_id);
    unsigned char *pkt;
    int len = nfq_get_payload(nfa, &pkt);
    int r = (len < 0) ? -1 : process(pkt, len, nfq_get_indev(nfa), outbuf);
    if (r < 0)  return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    if (r == 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)r, outbuf);
}

/* ------------------------------------------------------------------ PSK */
static size_t load_psk(const char *path, uint8_t *out, size_t max) {
    struct stat sb;
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("cannot open PSK file");
    if (fstat(fd, &sb) < 0 || !S_ISREG(sb.st_mode) || (sb.st_mode & 077))
        die("PSK file must be a regular file with permissions 0600 (chmod 600 FILE)");
    ssize_t n = read(fd, out, max);
    close(fd);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ')) n--;
    if (n < 16) die("PSK too short (need at least 16 bytes)");
    return (size_t)n;
}

static void on_signal(int s) { (void)s; stop_flag = 1; }

static void print_stats(void) {
    fprintf(stderr, "stats: encrypted=%llu decrypted=%llu drop_auth=%llu drop_replay=%llu drop_other=%llu enobufs=%llu\n",
            (unsigned long long)st.enc, (unsigned long long)st.dec, (unsigned long long)st.drop_auth,
            (unsigned long long)st.drop_replay, (unsigned long long)st.drop_other, (unsigned long long)st.enobufs);
}

/* ================================================================ SELF-TEST */
static int T_pass, T_fail;
#define CHECK(c) do { if (c) T_pass++; else { T_fail++; printf("  FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static void reset_session(const uint8_t *tx, const uint8_t *rx) {
    memcpy(tx_key, tx, KEY_LEN); memcpy(rx_key, rx, KEY_LEN);
    tx_ctr = 0; memset(&rw, 0, sizeof rw);
}

static int mk_pkt(uint8_t *p, const uint8_t *data, int dl, uint16_t dport) {
    memset(p, 0, 40);
    p[0] = 0x45; p[2] = (uint8_t)((40 + dl) >> 8); p[3] = (uint8_t)(40 + dl);
    p[8] = 64; p[9] = IPPROTO_TCP;
    p[12] = 10; p[14] = 1; p[15] = 2;                 /* 10.0.1.2 */
    p[16] = 10; p[18] = 3; p[19] = 2;                 /* 10.0.3.2 */
    p[20] = 40000 >> 8; p[21] = 40000 & 255;          /* sport */
    p[22] = (uint8_t)(dport >> 8); p[23] = (uint8_t)dport;
    p[26] = 0x03; p[27] = 0xE8;                       /* seq 1000 */
    p[31] = 77;                                       /* ack */
    p[32] = 0x50; p[33] = 0x18;                       /* doff=5, PSH|ACK */
    p[34] = 0xff; p[35] = 0xff;                       /* window */
    if (dl) memcpy(p + 40, data, (size_t)dl);
    fix_checksums(p);
    return 40 + dl;
}

static int csum_ok(const uint8_t *p) {
    const struct iphdr *ip = (const struct iphdr *)p;
    int ihl = ip->ihl * 4, tl = ntohs(ip->tot_len) - ihl;
    if (fold(sum16(p, (size_t)ihl, 0)) != 0) return 0;
    uint32_t s = sum16(&ip->saddr, 4, 0);
    s = sum16(&ip->daddr, 4, s);
    s += IPPROTO_TCP; s += (uint32_t)tl;
    return fold(sum16(p + ihl, (size_t)tl, s)) == 0;
}

static uint64_t pkt_ctr(const uint8_t *p, int n) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) c = (c << 8) | p[n - 8 + i];
    return c;
}

static int hs_test(const uint8_t *pi, size_t li, const uint8_t *pr, size_t lr, int *match) {
    int sv[2], pp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) || pipe(pp)) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]); close(pp[0]);
        int rc = hs_responder(sv[1], pr, lr);
        close(sv[1]);
        uint8_t o[65]; o[0] = (rc == 0); memcpy(o + 1, tx_key, 32); memcpy(o + 33, rx_key, 32);
        if (write(pp[1], o, sizeof o) < 0) _exit(1);
        _exit(0);
    }
    close(sv[1]); close(pp[1]);
    int rc = hs_initiator(sv[0], pi, li);
    close(sv[0]);
    uint8_t o[65] = {0};
    if (read(pp[0], o, sizeof o) < 0) o[0] = 0;
    waitpid(pid, NULL, 0); close(pp[0]);
    *match = (rc == 0 && o[0] == 1 && !memcmp(tx_key, o + 33, 32) && !memcmp(rx_key, o + 1, 32) &&
              memcmp(tx_key, rx_key, 32) != 0);
    return rc;
}

static int selftest(void) {
    uint8_t k[KEY_LEN], k2[KEY_LEN];
    uint8_t pkt[2048], enc[2048], enc2[2048], dec[2048], bad[2048];
    const uint8_t msg[] = "hello secure world";
    int ml = (int)sizeof msg - 1;
    RAND_bytes(k, KEY_LEN); RAND_bytes(k2, KEY_LEN);
    inside_idx = 1; peer_idx = 2; svc_port = 5000;
    int n = mk_pkt(pkt, msg, ml, 5000), e, d;

    printf("[1] round trip\n");
    reset_session(k, k);
    e = process(pkt, n, 1, enc);
    CHECK(e == n + 24);
    CHECK(csum_ok(enc));
    CHECK(memcmp(enc + 40, msg, (size_t)ml) != 0);
    CHECK(memcmp(enc + 12, pkt + 12, 8) == 0);               /* IPs preserved */
    CHECK(memcmp(enc + 20, pkt + 20, 16) == 0);              /* TCP ports/seq/ack preserved */
    d = process(enc, e, 2, dec);
    CHECK(d == n && memcmp(dec, pkt, (size_t)n) == 0 && csum_ok(dec));

    printf("[2] replay rejected\n");
    CHECK(process(enc, e, 2, dec) < 0);

    printf("[3] tampering rejected (ciphertext, tag, counter, every header field)\n");
    int offs[] = { 40, 40 + ml, 40 + ml + 16, 12, 16, 20, 22, 24, 28, 33, 34 };  /* ct, tag, ctr, saddr, daddr, sport, dport, seq, ack, flags, window */
    for (unsigned i = 0; i < sizeof offs / sizeof *offs; i++) {
        reset_session(k, k);
        e = process(pkt, n, 1, enc);
        memcpy(bad, enc, (size_t)e); bad[offs[i]] ^= 1;
        fix_checksums(bad);
        int r = process(bad, e, 2, dec);
        /* offset 22 = dest port: changing it makes the flow "not selected" (iptables would not
         * even queue it), so it is passed through still encrypted; it must never be decrypted. */
        CHECK(offs[i] == 22 ? r == 0 : r < 0);
    }

    printf("[4] wrong key rejected\n");
    reset_session(k, k);
    e = process(pkt, n, 1, enc);
    reset_session(k2, k2);
    CHECK(process(enc, e, 2, dec) < 0);

    printf("[5] empty-payload segments (SYN/ACK) are protected too\n");
    int sn = mk_pkt(pkt, NULL, 0, 5000);
    reset_session(k, k);
    e = process(pkt, sn, 1, enc);
    CHECK(e == sn + 24);
    d = process(enc, e, 2, dec);
    CHECK(d == sn && memcmp(dec, pkt, (size_t)sn) == 0);
    CHECK(process(pkt, sn, 2, dec) < 0);                      /* unprotected injected segment dropped */
    n = mk_pkt(pkt, msg, ml, 5000);

    printf("[6] nonce counters unique and strictly increasing over 100000 packets\n");
    reset_session(k, k);
    int uniq = 1; uint64_t prev = 0;
    for (int i = 0; i < 100000; i++) {
        e = process(pkt, n, 1, enc);
        uint64_t c = pkt_ctr(enc, e);
        if (i == 0) memcpy(enc2, enc, (size_t)e);
        if (i > 0 && c != prev + 1) uniq = 0;
        if (i == 0 && c != 0) uniq = 0;
        prev = c;
    }
    CHECK(uniq);
    CHECK(memcmp(enc + 40, enc2 + 40, (size_t)ml) != 0);     /* same plaintext, different ciphertext */

    printf("[7] reordering inside window accepted, replays still rejected\n");
    reset_session(k, k);
    uint8_t pk[5][128]; int pl_[5];
    for (int i = 0; i < 5; i++) pl_[i] = process(pkt, n, 1, pk[i]);
    int order[5] = { 4, 2, 3, 0, 1 };
    for (int i = 0; i < 5; i++) CHECK(process(pk[order[i]], pl_[order[i]], 2, dec) > 0);
    for (int i = 0; i < 5; i++) CHECK(process(pk[i], pl_[i], 2, dec) < 0);

    printf("[8] packets older than the window rejected\n");
    reset_session(k, k);
    e = process(pkt, n, 1, enc2);                             /* ctr 0 */
    for (int i = 0; i < 1500; i++) e = process(pkt, n, 1, enc);
    CHECK(process(enc, e, 2, dec) > 0);
    CHECK(process(enc2, n + 24, 2, dec) < 0);

    printf("[9] policy checks\n");
    reset_session(k, k);
    CHECK(process(pkt, n, 99, dec) < 0);                      /* unknown ingress */
    uint8_t other[128]; int on = mk_pkt(other, msg, ml, 80); other[21] = 0x51;
    CHECK(process(other, on, 1, dec) == 0);                   /* not selected: untouched */
    memcpy(bad, pkt, (size_t)n); bad[6] = 0x20;               /* fragment */
    CHECK(process(bad, n, 1, dec) < 0);
    CHECK(process(pkt, n - 5, 1, dec) < 0);                   /* truncated */
    tx_ctr = PKT_LIMIT;
    CHECK(process(pkt, n, 1, dec) < 0);                       /* counter exhausted: fail closed */

    printf("[10] authenticated DH handshake (fork + socketpair)\n");
    const uint8_t psk1[] = "correct horse battery staple", psk2[] = "correct horse battery stapl3";
    int match = 0;
    CHECK(hs_test(psk1, sizeof psk1 - 1, psk1, sizeof psk1 - 1, &match) == 0 && match);
    CHECK(hs_test(psk1, sizeof psk1 - 1, psk2, sizeof psk2 - 1, &match) != 0 && !match);

    printf("\nselftest: %d passed, %d failed\n", T_pass, T_fail);
    return T_fail ? 1 : 0;
}

/* ====================================================================== main */
static void usage(const char *p) {
    fprintf(stderr,
        "usage: %s --role initiator|responder --inside IF --peer-if IF --local IP --peer IP\n"
        "          --psk-file FILE [--port 5000] [--ctrl-port 6000] [--queue 0] [-v] [--tamper]\n"
        "       %s --selftest\n", p, p);
}

int main(int argc, char **argv) {
    const char *role = NULL, *inside = NULL, *peerif = NULL, *local = NULL, *peer = NULL, *pskf = NULL;
    int selftest_flag = 0;
    static struct option lo[] = {
        {"role", 1, 0, 'r'}, {"inside", 1, 0, 'i'}, {"peer-if", 1, 0, 'p'}, {"local", 1, 0, 'l'},
        {"peer", 1, 0, 'P'}, {"psk-file", 1, 0, 'k'}, {"port", 1, 0, 's'}, {"ctrl-port", 1, 0, 'c'},
        {"queue", 1, 0, 'q'}, {"verbose", 0, 0, 'v'}, {"tamper", 0, 0, 't'}, {"selftest", 0, 0, 'T'},
        {0, 0, 0, 0} };
    int o;
    while ((o = getopt_long(argc, argv, "v", lo, NULL)) != -1) {
        switch (o) {
        case 'r': role = optarg; break;     case 'i': inside = optarg; break;
        case 'p': peerif = optarg; break;   case 'l': local = optarg; break;
        case 'P': peer = optarg; break;     case 'k': pskf = optarg; break;
        case 's': svc_port = atoi(optarg); break;   case 'c': ctrl_port = atoi(optarg); break;
        case 'q': queue_num = atoi(optarg); break;  case 'v': verbose = 1; break;
        case 't': tamper = 1; break;        case 'T': selftest_flag = 1; break;
        default: usage(argv[0]); return 1;
        }
    }
    if (selftest_flag) return selftest();
    if (!role || !inside || !peerif || !local || !peer || !pskf) { usage(argv[0]); return 1; }
    int initiator = !strcmp(role, "initiator");
    if (!initiator && strcmp(role, "responder")) die("role must be initiator|responder");

    inside_idx = if_nametoindex(inside);
    peer_idx   = if_nametoindex(peerif);
    if (!inside_idx || !peer_idx) die("unknown interface (run inside the right network namespace?)");

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;                  /* no SA_RESTART: blocking calls return EINTR */
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);

    uint8_t psk[256];
    size_t pl = load_psk(pskf, psk, sizeof psk);

    /* 1) authenticated session first; until the queue listener exists, the NFQUEUE
     *    iptables rules have no reader and the kernel drops selected traffic. */
    establish_session(initiator, local, peer, psk, pl);
    OPENSSL_cleanse(psk, sizeof psk);
    fprintf(stderr, "session established (%s + PSK auth + key confirmation)\n", DH_GROUP);

    /* 2) packet processing */
    struct nfq_handle *h = nfq_open();
    if (!h) die("nfq_open");
    struct nfq_q_handle *qh = nfq_create_queue(h, (uint16_t)queue_num, &cb, NULL);
    if (!qh) die("nfq_create_queue (queue busy?)");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) die("nfq_set_mode");
    nfq_set_queue_maxlen(qh, 4096);

    int fd = nfq_fd(h);
    static char buf[MAXPKT + 4096] __attribute__((aligned(8)));
    fprintf(stderr, "gateway running: encrypt on %s, decrypt on %s, port %d\n", inside, peerif, svc_port);
    while (!stop_flag) {
        ssize_t rv = recv(fd, buf, sizeof buf, 0);
        if (rv < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) { st.enobufs++; continue; }
            perror("recv"); break;
        }
        nfq_handle_packet(h, buf, (int)rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
    print_stats();
    OPENSSL_cleanse(tx_key, sizeof tx_key); OPENSSL_cleanse(rx_key, sizeof rx_key);
    return 0;
}
