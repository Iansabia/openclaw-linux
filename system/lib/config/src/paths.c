/*
 * kelp-linux :: libkelp-config
 * paths.c - XDG-compliant path resolution and directory creation
 *
 * SPDX-License-Identifier: MIT
 */

#include "kelp/paths.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ */
/* Internal helpers                                                         */
/* ------------------------------------------------------------------------ */

/**
 * Return the user's home directory (heap-allocated copy).
 * Falls back to getpwuid() if $HOME is not set.
 */
static char *
get_home(void)
{
    const char *h = getenv("HOME");
    if (h && h[0])
        return strdup(h);

    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_dir)
        return strdup(pw->pw_dir);

    /* Last resort -- should never happen on a sane system. */
    return strdup("/");
}

/**
 * Build "<base>/<tail>" on the heap.
 */
static char *
join_path(const char *base, const char *tail)
{
    if (!base || !tail)
        return NULL;

    size_t blen = strlen(base);
    size_t tlen = strlen(tail);
    /* +2: one for '/' separator, one for NUL */
    char *out = malloc(blen + 1 + tlen + 1);
    if (!out)
        return NULL;

    memcpy(out, base, blen);
    if (blen > 0 && base[blen - 1] != '/')
        out[blen++] = '/';
    memcpy(out + blen, tail, tlen);
    out[blen + tlen] = '\0';
    return out;
}

/**
 * Recursive mkdir (equivalent to `mkdir -p`).
 * Returns 0 on success, -1 on error.
 */
static int
mkdirp(const char *path, mode_t mode)
{
    if (!path || !path[0])
        return -1;

    char *tmp = strdup(path);
    if (!tmp)
        return -1;

    size_t len = strlen(tmp);
    /* Strip trailing slash */
    if (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                free(tmp);
                return -1;
            }
            *p = '/';
        }
    }

    int rc = 0;
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        rc = -1;

    free(tmp);
    return rc;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

char *
kelp_paths_config_dir(void)
{
    const char *env;

    env = getenv("KELP_CONFIG_DIR");
    if (env && env[0])
        return strdup(env);

    env = getenv("XDG_CONFIG_HOME");
    if (env && env[0])
        return join_path(env, "kelp");

    char *home = get_home();
    if (!home)
        return NULL;
    char *cfg = join_path(home, ".config/kelp");
    free(home);
    return cfg;
}

char *
kelp_paths_data_dir(void)
{
    const char *env;

    env = getenv("KELP_DATA_DIR");
    if (env && env[0])
        return strdup(env);

    env = getenv("XDG_DATA_HOME");
    if (env && env[0])
        return join_path(env, "kelp");

    char *home = get_home();
    if (!home)
        return NULL;
    char *data = join_path(home, ".local/share/kelp");
    free(home);
    return data;
}

char *
kelp_paths_runtime_dir(void)
{
    const char *env;

    env = getenv("KELP_RUNTIME_DIR");
    if (env && env[0])
        return strdup(env);

    env = getenv("XDG_RUNTIME_DIR");
    if (env && env[0])
        return join_path(env, "kelp");

    return strdup("/run/kelp");
}

char *
kelp_paths_socket(void)
{
    char *rtdir = kelp_paths_runtime_dir();
    if (!rtdir)
        return NULL;
    char *sock = join_path(rtdir, "kelp.sock");
    free(rtdir);
    return sock;
}

int
kelp_paths_ensure_dirs(void)
{
    int rc = 0;

    char *cfg = kelp_paths_config_dir();
    char *data = kelp_paths_data_dir();
    char *run  = kelp_paths_runtime_dir();

    if (!cfg || !data || !run) {
        rc = -1;
        goto out;
    }

    if (mkdirp(cfg,  0755) != 0) { rc = -1; goto out; }
    if (mkdirp(data, 0755) != 0) { rc = -1; goto out; }
    if (mkdirp(run,  0700) != 0) { rc = -1; goto out; }

out:
    free(cfg);
    free(data);
    free(run);
    return rc;
}

char *
kelp_paths_expand(const char *path)
{
    if (!path)
        return NULL;

    /*
     * Phase 1: tilde expansion.
     *
     * Only a leading "~" (followed by '/' or NUL) is expanded.
     */
    const char *src = path;
    char *after_tilde = NULL;

    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        char *home = get_home();
        if (!home)
            return NULL;
        size_t hlen = strlen(home);
        size_t rest = strlen(path + 1); /* skip '~' */
        after_tilde = malloc(hlen + rest + 1);
        if (!after_tilde) {
            free(home);
            return NULL;
        }
        memcpy(after_tilde, home, hlen);
        memcpy(after_tilde + hlen, path + 1, rest);
        after_tilde[hlen + rest] = '\0';
        free(home);
        src = after_tilde;
    }

    /*
     * Phase 2: environment variable substitution.
     *
     * Patterns:
     *   ${VAR}          -> value of VAR (empty string if unset)
     *   ${VAR:-default} -> value of VAR, or "default" if unset/empty
     */
    size_t cap = strlen(src) + 256;
    char *out = malloc(cap);
    if (!out) {
        free(after_tilde);
        return NULL;
    }
    size_t olen = 0;

#define ENSURE_SPACE(need)                                     \
    do {                                                       \
        while (olen + (need) >= cap) {                         \
            cap *= 2;                                          \
            char *_tmp = realloc(out, cap);                    \
            if (!_tmp) { free(out); free(after_tilde); return NULL; } \
            out = _tmp;                                        \
        }                                                      \
    } while (0)

    for (const char *p = src; *p; ) {
        if (p[0] == '$' && p[1] == '{') {
            /* Find closing brace */
            const char *end = strchr(p + 2, '}');
            if (!end) {
                /* Malformed -- copy literally */
                ENSURE_SPACE(1);
                out[olen++] = *p++;
                continue;
            }

            /* Extract the text between ${ and } */
            size_t inner_len = (size_t)(end - (p + 2));
            char inner[inner_len + 1];
            memcpy(inner, p + 2, inner_len);
            inner[inner_len] = '\0';

            /* Check for :-default */
            const char *def_val = "";
            char *colon = strstr(inner, ":-");
            char var_name[inner_len + 1];
            if (colon) {
                size_t nlen = (size_t)(colon - inner);
                memcpy(var_name, inner, nlen);
                var_name[nlen] = '\0';
                def_val = colon + 2;
            } else {
                memcpy(var_name, inner, inner_len + 1);
            }

            const char *val = getenv(var_name);
            if (!val || !val[0])
                val = def_val;

            size_t vlen = strlen(val);
            ENSURE_SPACE(vlen);
            memcpy(out + olen, val, vlen);
            olen += vlen;

            p = end + 1; /* skip past '}' */
        } else {
            ENSURE_SPACE(1);
            out[olen++] = *p++;
        }
    }

#undef ENSURE_SPACE

    out[olen] = '\0';
    free(after_tilde);
    return out;
}
