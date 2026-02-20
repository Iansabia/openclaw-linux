/*
 * clawd-linux :: libclawd-net
 * mdns.c - mDNS service discovery (Avahi backend)
 *
 * Compiled with full Avahi support when HAVE_AVAHI is defined.
 * Otherwise, all functions return -1 (unsupported) stubs.
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/mdns.h>
#include <clawd/log.h>

#ifdef HAVE_AVAHI

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/alternative.h>

#include <stdlib.h>
#include <string.h>

/* ---- Static state for publishing ---------------------------------------- */

static AvahiSimplePoll  *s_poll   = NULL;
static AvahiClient      *s_client = NULL;
static AvahiEntryGroup  *s_group  = NULL;
static char             *s_name   = NULL;
static char             *s_type   = NULL;
static int               s_port   = 0;

/* ---- Publish callbacks -------------------------------------------------- */

static void entry_group_cb(AvahiEntryGroup *g, AvahiEntryGroupState state,
                           void *ud)
{
    (void)ud;

    switch (state) {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        CLAWD_INFO("mDNS: service '%s' published on %s port %d",
                   s_name, s_type, s_port);
        break;
    case AVAHI_ENTRY_GROUP_COLLISION: {
        /* Rename and retry */
        char *alt = avahi_alternative_service_name(s_name);
        CLAWD_WARN("mDNS: name collision, renaming '%s' -> '%s'",
                   s_name, alt);
        free(s_name);
        s_name = strdup(alt);
        avahi_free(alt);

        avahi_entry_group_reset(g);
        avahi_entry_group_add_service(g, AVAHI_IF_UNSPEC,
                                      AVAHI_PROTO_UNSPEC, 0,
                                      s_name, s_type, NULL, NULL,
                                      (uint16_t)s_port, NULL);
        avahi_entry_group_commit(g);
        break;
    }
    case AVAHI_ENTRY_GROUP_FAILURE:
        CLAWD_ERROR("mDNS: entry group failure: %s",
                    avahi_strerror(avahi_client_errno(
                        avahi_entry_group_get_client(g))));
        avahi_simple_poll_quit(s_poll);
        break;
    default:
        break;
    }
}

static void publish_client_cb(AvahiClient *c, AvahiClientState state,
                              void *ud)
{
    (void)ud;

    switch (state) {
    case AVAHI_CLIENT_S_RUNNING:
        if (!s_group) {
            s_group = avahi_entry_group_new(c, entry_group_cb, NULL);
            if (!s_group) {
                CLAWD_ERROR("mDNS: avahi_entry_group_new failed");
                avahi_simple_poll_quit(s_poll);
                return;
            }
        }
        if (avahi_entry_group_is_empty(s_group)) {
            int ret = avahi_entry_group_add_service(
                s_group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, 0,
                s_name, s_type, NULL, NULL, (uint16_t)s_port, NULL);
            if (ret < 0) {
                CLAWD_ERROR("mDNS: failed to add service: %s",
                            avahi_strerror(ret));
                avahi_simple_poll_quit(s_poll);
                return;
            }
            avahi_entry_group_commit(s_group);
        }
        break;
    case AVAHI_CLIENT_FAILURE:
        CLAWD_ERROR("mDNS: client failure: %s",
                    avahi_strerror(avahi_client_errno(c)));
        avahi_simple_poll_quit(s_poll);
        break;
    default:
        break;
    }
}

/* ---- Browse callbacks --------------------------------------------------- */

typedef struct {
    clawd_mdns_browse_cb cb;
    void                *ud;
} browse_ud_t;

static void resolve_cb(AvahiServiceResolver *r,
                       AvahiIfIndex iface,
                       AvahiProtocol protocol,
                       AvahiResolverEvent event,
                       const char *name,
                       const char *type,
                       const char *domain,
                       const char *host,
                       const AvahiAddress *addr,
                       uint16_t port,
                       AvahiStringList *txt,
                       AvahiLookupResultFlags flags,
                       void *ud)
{
    (void)iface; (void)protocol; (void)type; (void)domain;
    (void)addr; (void)txt; (void)flags;

    browse_ud_t *bud = (browse_ud_t *)ud;

    if (event == AVAHI_RESOLVER_FOUND) {
        bud->cb(name, host, (int)port, bud->ud);
    } else {
        CLAWD_WARN("mDNS: resolve failed for '%s': %s", name,
                   avahi_strerror(avahi_client_errno(
                       avahi_service_resolver_get_client(r))));
    }

    avahi_service_resolver_free(r);
}

static void browse_cb(AvahiServiceBrowser *b,
                      AvahiIfIndex iface,
                      AvahiProtocol protocol,
                      AvahiBrowserEvent event,
                      const char *name,
                      const char *type,
                      const char *domain,
                      AvahiLookupResultFlags flags,
                      void *ud)
{
    (void)flags;

    switch (event) {
    case AVAHI_BROWSER_NEW:
        avahi_service_resolver_new(
            avahi_service_browser_get_client(b),
            iface, protocol, name, type, domain,
            AVAHI_PROTO_UNSPEC, 0, resolve_cb, ud);
        break;
    case AVAHI_BROWSER_ALL_FOR_NOW:
        avahi_simple_poll_quit(
            (AvahiSimplePoll *)avahi_simple_poll_get(
                avahi_service_browser_get_client(b)));
        break;
    case AVAHI_BROWSER_FAILURE:
        CLAWD_ERROR("mDNS: browser failure: %s",
                    avahi_strerror(avahi_client_errno(
                        avahi_service_browser_get_client(b))));
        break;
    default:
        break;
    }
}

/* ---- Public API --------------------------------------------------------- */

int clawd_mdns_publish(const char *name, const char *type, int port)
{
    if (!name || !type || port <= 0) {
        CLAWD_ERROR("mDNS: invalid publish arguments");
        return -1;
    }

    /* Clean up previous publication if any */
    clawd_mdns_unpublish();

    s_name = strdup(name);
    s_type = strdup(type);
    s_port = port;
    if (!s_name || !s_type) {
        CLAWD_ERROR("mDNS: allocation failed");
        clawd_mdns_unpublish();
        return -1;
    }

    s_poll = avahi_simple_poll_new();
    if (!s_poll) {
        CLAWD_ERROR("mDNS: avahi_simple_poll_new failed");
        clawd_mdns_unpublish();
        return -1;
    }

    int error = 0;
    s_client = avahi_client_new(avahi_simple_poll_get(s_poll),
                                AVAHI_CLIENT_NO_FAIL,
                                publish_client_cb, NULL, &error);
    if (!s_client) {
        CLAWD_ERROR("mDNS: avahi_client_new failed: %s",
                    avahi_strerror(error));
        clawd_mdns_unpublish();
        return -1;
    }

    /*
     * Run the poll loop briefly to register the service.
     * In a real daemon this would run in a background thread.
     * For now, iterate a few times to allow registration.
     */
    for (int i = 0; i < 10; i++) {
        if (avahi_simple_poll_iterate(s_poll, 100) != 0)
            break;
    }

    return 0;
}

int clawd_mdns_browse(const char *type, clawd_mdns_browse_cb cb, void *ud)
{
    if (!type || !cb)
        return -1;

    AvahiSimplePoll *poll = avahi_simple_poll_new();
    if (!poll)
        return -1;

    int error = 0;
    AvahiClient *client = avahi_client_new(avahi_simple_poll_get(poll), 0,
                                           NULL, NULL, &error);
    if (!client) {
        CLAWD_ERROR("mDNS: browse client failed: %s", avahi_strerror(error));
        avahi_simple_poll_free(poll);
        return -1;
    }

    browse_ud_t bud = { .cb = cb, .ud = ud };

    AvahiServiceBrowser *browser = avahi_service_browser_new(
        client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, type, NULL,
        0, browse_cb, &bud);
    if (!browser) {
        CLAWD_ERROR("mDNS: browser creation failed");
        avahi_client_free(client);
        avahi_simple_poll_free(poll);
        return -1;
    }

    /* Run the poll loop for up to 3 seconds to discover services */
    for (int i = 0; i < 30; i++) {
        if (avahi_simple_poll_iterate(poll, 100) != 0)
            break;
    }

    avahi_service_browser_free(browser);
    avahi_client_free(client);
    avahi_simple_poll_free(poll);
    return 0;
}

void clawd_mdns_unpublish(void)
{
    if (s_group) {
        avahi_entry_group_free(s_group);
        s_group = NULL;
    }
    if (s_client) {
        avahi_client_free(s_client);
        s_client = NULL;
    }
    if (s_poll) {
        avahi_simple_poll_free(s_poll);
        s_poll = NULL;
    }
    free(s_name);  s_name = NULL;
    free(s_type);  s_type = NULL;
    s_port = 0;

    CLAWD_DEBUG("mDNS: unpublished");
}

#else /* !HAVE_AVAHI */

/* ---- Stub implementation when Avahi is not available -------------------- */

int clawd_mdns_publish(const char *name, const char *type, int port)
{
    (void)name; (void)type; (void)port;
    CLAWD_WARN("mDNS: Avahi not available -- publish is a no-op");
    return -1;
}

int clawd_mdns_browse(const char *type, clawd_mdns_browse_cb cb, void *ud)
{
    (void)type; (void)cb; (void)ud;
    CLAWD_WARN("mDNS: Avahi not available -- browse is a no-op");
    return -1;
}

void clawd_mdns_unpublish(void)
{
    /* nothing to do */
}

#endif /* HAVE_AVAHI */
