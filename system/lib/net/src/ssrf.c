/*
 * kelp-linux :: libkelp-net
 * ssrf.c - Server-Side Request Forgery prevention
 *
 * Resolves hostnames and checks whether the resulting IPs fall into
 * private/reserved ranges before allowing outbound requests.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/ssrf.h>
#include <kelp/err.h>
#include <kelp/log.h>

#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ---- Allow/block lists -------------------------------------------------- */

#define MAX_LIST_ENTRIES 256

static struct {
    pthread_mutex_t lock;
    char           *allow[MAX_LIST_ENTRIES];
    int             allow_count;
    char           *block[MAX_LIST_ENTRIES];
    int             block_count;
} ssrf_lists = {
    .lock        = PTHREAD_MUTEX_INITIALIZER,
    .allow_count = 0,
    .block_count = 0
};

void kelp_ssrf_allow_list_add(const char *host)
{
    if (!host)
        return;
    pthread_mutex_lock(&ssrf_lists.lock);
    if (ssrf_lists.allow_count < MAX_LIST_ENTRIES) {
        ssrf_lists.allow[ssrf_lists.allow_count++] = strdup(host);
    }
    pthread_mutex_unlock(&ssrf_lists.lock);
}

void kelp_ssrf_block_list_add(const char *host)
{
    if (!host)
        return;
    pthread_mutex_lock(&ssrf_lists.lock);
    if (ssrf_lists.block_count < MAX_LIST_ENTRIES) {
        ssrf_lists.block[ssrf_lists.block_count++] = strdup(host);
    }
    pthread_mutex_unlock(&ssrf_lists.lock);
}

void kelp_ssrf_lists_reset(void)
{
    pthread_mutex_lock(&ssrf_lists.lock);
    for (int i = 0; i < ssrf_lists.allow_count; i++) {
        free(ssrf_lists.allow[i]);
        ssrf_lists.allow[i] = NULL;
    }
    ssrf_lists.allow_count = 0;
    for (int i = 0; i < ssrf_lists.block_count; i++) {
        free(ssrf_lists.block[i]);
        ssrf_lists.block[i] = NULL;
    }
    ssrf_lists.block_count = 0;
    pthread_mutex_unlock(&ssrf_lists.lock);
}

static bool is_in_allow_list(const char *host)
{
    bool found = false;
    pthread_mutex_lock(&ssrf_lists.lock);
    for (int i = 0; i < ssrf_lists.allow_count; i++) {
        if (strcasecmp(ssrf_lists.allow[i], host) == 0) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&ssrf_lists.lock);
    return found;
}

static bool is_in_block_list(const char *host)
{
    bool found = false;
    pthread_mutex_lock(&ssrf_lists.lock);
    for (int i = 0; i < ssrf_lists.block_count; i++) {
        if (strcasecmp(ssrf_lists.block[i], host) == 0) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&ssrf_lists.lock);
    return found;
}

/* ---- Private IP checks -------------------------------------------------- */

/**
 * Check whether an IPv4 address (in network byte order) is in a private range.
 *
 * Blocked ranges:
 *   127.0.0.0/8     - loopback
 *   10.0.0.0/8      - RFC 1918 class A
 *   172.16.0.0/12   - RFC 1918 class B
 *   192.168.0.0/16  - RFC 1918 class C
 *   169.254.0.0/16  - link-local (includes cloud metadata 169.254.169.254)
 *   0.0.0.0/8       - "this" network
 *   100.64.0.0/10   - carrier-grade NAT (RFC 6598)
 *   192.0.0.0/24    - IETF protocol assignments
 *   192.0.2.0/24    - TEST-NET-1
 *   198.51.100.0/24 - TEST-NET-2
 *   203.0.113.0/24  - TEST-NET-3
 *   224.0.0.0/4     - multicast
 *   240.0.0.0/4     - reserved
 */
static bool is_private_ipv4(const struct in_addr *addr)
{
    uint32_t ip = ntohl(addr->s_addr);

    /* 127.0.0.0/8 -- loopback */
    if ((ip & 0xFF000000) == 0x7F000000)
        return true;

    /* 10.0.0.0/8 */
    if ((ip & 0xFF000000) == 0x0A000000)
        return true;

    /* 172.16.0.0/12 */
    if ((ip & 0xFFF00000) == 0xAC100000)
        return true;

    /* 192.168.0.0/16 */
    if ((ip & 0xFFFF0000) == 0xC0A80000)
        return true;

    /* 169.254.0.0/16 -- link-local, metadata endpoint */
    if ((ip & 0xFFFF0000) == 0xA9FE0000)
        return true;

    /* 0.0.0.0/8 */
    if ((ip & 0xFF000000) == 0x00000000)
        return true;

    /* 100.64.0.0/10 -- CGNAT */
    if ((ip & 0xFFC00000) == 0x64400000)
        return true;

    /* 192.0.0.0/24 */
    if ((ip & 0xFFFFFF00) == 0xC0000000)
        return true;

    /* 192.0.2.0/24 -- TEST-NET-1 */
    if ((ip & 0xFFFFFF00) == 0xC0000200)
        return true;

    /* 198.51.100.0/24 -- TEST-NET-2 */
    if ((ip & 0xFFFFFF00) == 0xC6336400)
        return true;

    /* 203.0.113.0/24 -- TEST-NET-3 */
    if ((ip & 0xFFFFFF00) == 0xCB007100)
        return true;

    /* 224.0.0.0/4 -- multicast */
    if ((ip & 0xF0000000) == 0xE0000000)
        return true;

    /* 240.0.0.0/4 -- reserved */
    if ((ip & 0xF0000000) == 0xF0000000)
        return true;

    return false;
}

/**
 * Check whether an IPv6 address is in a private/reserved range.
 *
 * Blocked:
 *   ::1/128   - loopback
 *   fc00::/7  - unique local addresses
 *   fe80::/10 - link-local
 *   ::ffff:0:0/96 - IPv4-mapped (checked via mapped IPv4)
 *   ::/128    - unspecified
 *   ::ffff:0:0:0/96 - IPv4-translated
 */
static bool is_private_ipv6(const struct in6_addr *addr)
{
    const uint8_t *b = addr->s6_addr;

    /* ::1 -- loopback */
    static const uint8_t loopback[16] = {
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
    };
    if (memcmp(b, loopback, 16) == 0)
        return true;

    /* :: -- unspecified */
    static const uint8_t unspec[16] = {0};
    if (memcmp(b, unspec, 16) == 0)
        return true;

    /* fc00::/7 -- unique local */
    if ((b[0] & 0xFE) == 0xFC)
        return true;

    /* fe80::/10 -- link-local */
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
        return true;

    /* ::ffff:x.x.x.x -- IPv4-mapped, check the embedded IPv4 */
    if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
        b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
        b[8] == 0 && b[9] == 0 && b[10] == 0xFF && b[11] == 0xFF) {
        struct in_addr v4;
        memcpy(&v4.s_addr, &b[12], 4);
        return is_private_ipv4(&v4);
    }

    return false;
}

/* ---- URL parsing -------------------------------------------------------- */

/**
 * Extract the hostname from a URL.
 * Returns a malloc'd string (caller frees), or NULL on failure.
 *
 * Handles: http://host:port/path, https://host/path, http://[ipv6]:port/path
 */
static char *extract_host(const char *url)
{
    if (!url)
        return NULL;

    /* Skip scheme */
    const char *p = strstr(url, "://");
    if (!p)
        return NULL;
    p += 3;

    /* Skip userinfo@ if present */
    const char *at = strchr(p, '@');
    const char *slash = strchr(p, '/');
    if (at && (!slash || at < slash))
        p = at + 1;

    /* Handle IPv6 literal [::1] */
    if (*p == '[') {
        const char *end = strchr(p, ']');
        if (!end)
            return NULL;
        size_t len = (size_t)(end - p - 1);
        char *host = malloc(len + 1);
        if (!host)
            return NULL;
        memcpy(host, p + 1, len);
        host[len] = '\0';
        return host;
    }

    /* Find end of host (port or path) */
    const char *end = p;
    while (*end && *end != ':' && *end != '/' && *end != '?' && *end != '#')
        end++;

    size_t len = (size_t)(end - p);
    if (len == 0)
        return NULL;

    char *host = malloc(len + 1);
    if (!host)
        return NULL;
    memcpy(host, p, len);
    host[len] = '\0';
    return host;
}

/* ---- Public API --------------------------------------------------------- */

bool kelp_ssrf_is_private_ip(const char *host)
{
    if (!host)
        return true; /* null host is treated as private for safety */

    /* Try direct parse as IPv4 */
    struct in_addr addr4;
    if (inet_pton(AF_INET, host, &addr4) == 1)
        return is_private_ipv4(&addr4);

    /* Try direct parse as IPv6 */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host, &addr6) == 1)
        return is_private_ipv6(&addr6);

    /* It is a hostname -- resolve it and check all resulting addresses */
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *res = NULL;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0) {
        KELP_WARN("SSRF: getaddrinfo(%s) failed: %s",
                   host, gai_strerror(rc));
        return true; /* unresolvable hosts are treated as blocked */
    }

    bool is_private = false;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
            if (is_private_ipv4(&sa->sin_addr)) {
                is_private = true;
                break;
            }
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ai->ai_addr;
            if (is_private_ipv6(&sa6->sin6_addr)) {
                is_private = true;
                break;
            }
        }
    }

    freeaddrinfo(res);
    return is_private;
}

int kelp_ssrf_check(const char *url)
{
    if (!url) {
        KELP_WARN("SSRF: NULL URL blocked");
        return -1;
    }

    char *host = extract_host(url);
    if (!host) {
        KELP_WARN("SSRF: failed to extract host from URL: %s", url);
        return -1;
    }

    /* Check explicit block list first (always wins) */
    if (is_in_block_list(host)) {
        KELP_WARN("SSRF: host '%s' is in block list", host);
        free(host);
        return -1;
    }

    /* Check explicit allow list (bypasses private IP check) */
    if (is_in_allow_list(host)) {
        KELP_DEBUG("SSRF: host '%s' is in allow list", host);
        free(host);
        return 0;
    }

    /* Resolve and check all addresses against private ranges */
    if (kelp_ssrf_is_private_ip(host)) {
        KELP_WARN("SSRF: blocked request to private host '%s'", host);
        free(host);
        return -1;
    }

    KELP_DEBUG("SSRF: host '%s' passed validation", host);
    free(host);
    return 0;
}
