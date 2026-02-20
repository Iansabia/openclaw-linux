/*
 * clawd-linux :: libclawd-net
 * ssrf.h - Server-Side Request Forgery prevention
 *
 * Blocks requests to private/internal IP ranges and cloud metadata endpoints.
 *
 * Blocked ranges:
 *   127.0.0.0/8       (loopback)
 *   10.0.0.0/8        (private class A)
 *   172.16.0.0/12     (private class B)
 *   192.168.0.0/16    (private class C)
 *   169.254.0.0/16    (link-local, includes metadata 169.254.169.254)
 *   ::1               (IPv6 loopback)
 *   fc00::/7          (IPv6 unique-local)
 *   fe80::/10         (IPv6 link-local)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_SSRF_H
#define CLAWD_SSRF_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check whether a URL is safe to request.
 *
 * Resolves the hostname and validates the resulting IP address(es)
 * against the blocked private ranges and any custom block/allow lists.
 *
 * @param url  The full URL to check.
 * @return 0 if the URL is safe, -1 if the request should be blocked.
 */
int clawd_ssrf_check(const char *url);

/**
 * Test whether a hostname or IP string resolves to a private address.
 */
bool clawd_ssrf_is_private_ip(const char *host);

/**
 * Add a host to the explicit allow list.
 * Hosts on the allow list bypass the private-IP check.
 */
void clawd_ssrf_allow_list_add(const char *host);

/**
 * Add a host to the explicit block list.
 * Hosts on the block list are always rejected, even if they resolve
 * to public addresses.
 */
void clawd_ssrf_block_list_add(const char *host);

/**
 * Reset both the allow and block lists (useful for testing).
 */
void clawd_ssrf_lists_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_SSRF_H */
