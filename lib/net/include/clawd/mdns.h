/*
 * clawd-linux :: libclawd-net
 * mdns.h - mDNS service discovery (Avahi backend)
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_MDNS_H
#define CLAWD_MDNS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback invoked when a service is discovered during browsing.
 *
 * @param name  Service instance name.
 * @param host  Hostname or IP of the service.
 * @param port  Port number.
 * @param ud    User data passed to clawd_mdns_browse().
 */
typedef void (*clawd_mdns_browse_cb)(const char *name, const char *host,
                                     int port, void *ud);

/**
 * Publish a service on the local network via mDNS.
 *
 * @param name  Human-readable service name (e.g. "clawd gateway").
 * @param type  Service type string (e.g. "_clawd._tcp").
 * @param port  Port number the service is listening on.
 * @return 0 on success, -1 on failure or if Avahi is not available.
 */
int clawd_mdns_publish(const char *name, const char *type, int port);

/**
 * Browse for services of the given type on the local network.
 *
 * This is a blocking call that runs the Avahi event loop for a brief
 * period.  The callback is invoked for each discovered service.
 *
 * @param type  Service type to browse (e.g. "_clawd._tcp").
 * @param cb    Callback invoked for each discovered service.
 * @param ud    User data passed to the callback.
 * @return 0 on success, -1 on failure or if Avahi is not available.
 */
int clawd_mdns_browse(const char *type, clawd_mdns_browse_cb cb, void *ud);

/**
 * Unpublish any previously published mDNS service and release resources.
 */
void clawd_mdns_unpublish(void);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_MDNS_H */
