/*
 * kelp-linux :: libkelp-security
 * path_scan.c - Path scanning / filtering
 *
 * Pattern-based path filter using fnmatch(3) glob matching.
 * Patterns are evaluated in insertion order; the first match wins.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/path_scan.h>
#include <kelp/log.h>

#include <fnmatch.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---- internal types ----------------------------------------------------- */

typedef struct {
    char *pattern;
    bool  deny;     /* true = deny on match, false = allow on match */
} scan_rule_t;

struct kelp_path_scanner {
    scan_rule_t *rules;
    size_t       count;
    size_t       cap;
};

/* ---- helpers ------------------------------------------------------------ */

static int scanner_grow(kelp_path_scanner_t *s)
{
    size_t new_cap = s->cap ? s->cap * 2 : 16;
    scan_rule_t *tmp = realloc(s->rules, new_cap * sizeof(scan_rule_t));
    if (!tmp)
        return -1;
    s->rules = tmp;
    s->cap   = new_cap;
    return 0;
}

/* ---- public API --------------------------------------------------------- */

kelp_path_scanner_t *kelp_path_scanner_new(void)
{
    kelp_path_scanner_t *s = calloc(1, sizeof(*s));
    return s;
}

void kelp_path_scanner_free(kelp_path_scanner_t *s)
{
    if (!s)
        return;

    for (size_t i = 0; i < s->count; i++)
        free(s->rules[i].pattern);

    free(s->rules);
    free(s);
}

void kelp_path_scanner_add_pattern(kelp_path_scanner_t *s,
                                    const char *glob_pattern,
                                    bool deny)
{
    if (!s || !glob_pattern)
        return;

    if (s->count >= s->cap) {
        if (scanner_grow(s) != 0) {
            KELP_ERROR("path_scan: allocation failure adding pattern");
            return;
        }
    }

    s->rules[s->count].pattern = strdup(glob_pattern);
    if (!s->rules[s->count].pattern) {
        KELP_ERROR("path_scan: strdup failure for pattern: %s", glob_pattern);
        return;
    }

    s->rules[s->count].deny = deny;
    s->count++;
}

bool kelp_path_scanner_check(const kelp_path_scanner_t *s, const char *path)
{
    if (!s || !path)
        return false;

    /* Extract the basename for pattern matching against simple globs. */
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;

    for (size_t i = 0; i < s->count; i++) {
        const scan_rule_t *r = &s->rules[i];
        bool matched = false;

        /* Try matching the full path first. */
        if (fnmatch(r->pattern, path, FNM_PATHNAME) == 0) {
            matched = true;
        }
        /* Then try matching just the basename (for patterns like "*.env"). */
        else if (fnmatch(r->pattern, basename, 0) == 0) {
            matched = true;
        }

        if (matched) {
            /* deny=true means this is a deny rule -> return false (not allowed).
             * deny=false means this is an allow rule -> return true (allowed). */
            return !r->deny;
        }
    }

    /* No matching rule -- allowed by default. */
    return true;
}

void kelp_path_scanner_add_defaults(kelp_path_scanner_t *s)
{
    if (!s)
        return;

    /* Environment / secret files. */
    kelp_path_scanner_add_pattern(s, "*.env",         true);
    kelp_path_scanner_add_pattern(s, ".env",          true);
    kelp_path_scanner_add_pattern(s, ".env.*",        true);

    /* SSH keys and config. */
    kelp_path_scanner_add_pattern(s, ".ssh/*",        true);
    kelp_path_scanner_add_pattern(s, "*/.ssh/*",      true);

    /* Certificates and private keys. */
    kelp_path_scanner_add_pattern(s, "*.pem",         true);
    kelp_path_scanner_add_pattern(s, "*.key",         true);
    kelp_path_scanner_add_pattern(s, "*.p12",         true);
    kelp_path_scanner_add_pattern(s, "*.pfx",         true);

    /* Credential files. */
    kelp_path_scanner_add_pattern(s, "credentials*",  true);
    kelp_path_scanner_add_pattern(s, "*credentials*", true);

    /* Secret files. */
    kelp_path_scanner_add_pattern(s, "*secret*",      true);

    /* Token / password files. */
    kelp_path_scanner_add_pattern(s, "*.token",       true);
    kelp_path_scanner_add_pattern(s, "*password*",    true);

    /* System pseudo-filesystems. */
    kelp_path_scanner_add_pattern(s, "/proc/*",       true);
    kelp_path_scanner_add_pattern(s, "/sys/*",        true);

    /* Docker / container secrets. */
    kelp_path_scanner_add_pattern(s, "*.dockercfg",   true);
    kelp_path_scanner_add_pattern(s, ".docker/config.json", true);

    /* AWS / cloud credentials. */
    kelp_path_scanner_add_pattern(s, ".aws/*",        true);
    kelp_path_scanner_add_pattern(s, "*/.aws/*",      true);
    kelp_path_scanner_add_pattern(s, ".gcloud/*",     true);

    /* GPG private keys. */
    kelp_path_scanner_add_pattern(s, "*.gpg",         true);
    kelp_path_scanner_add_pattern(s, "*.asc",         true);

    KELP_INFO("path_scan: added default deny patterns");
}
