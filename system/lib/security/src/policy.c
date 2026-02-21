/*
 * kelp-linux :: libkelp-security
 * policy.c - Tool policy enforcement
 *
 * Stores an ordered list of rules.  On each check the first matching rule
 * wins.  Glob matching uses fnmatch(3).
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/policy.h>
#include <kelp/log.h>
#include <kelp/json.h>

#include <fnmatch.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ---- internal types ----------------------------------------------------- */

/** Internal copy of a rule (owns its strings). */
typedef struct {
    char                  *tool_name;
    char                  *pattern;
    kelp_policy_action_t  action;
    char                  *reason;
} rule_t;

struct kelp_policy {
    rule_t *rules;
    size_t  count;
    size_t  cap;
};

/* ---- helpers ------------------------------------------------------------ */

static int policy_grow(kelp_policy_t *p)
{
    size_t new_cap = p->cap ? p->cap * 2 : 16;
    rule_t *tmp = realloc(p->rules, new_cap * sizeof(rule_t));
    if (!tmp)
        return -1;
    p->rules = tmp;
    p->cap   = new_cap;
    return 0;
}

static char *safe_strdup(const char *s)
{
    return s ? strdup(s) : NULL;
}

static void rule_free(rule_t *r)
{
    if (!r) return;
    free(r->tool_name);
    free(r->pattern);
    free(r->reason);
    r->tool_name = NULL;
    r->pattern   = NULL;
    r->reason    = NULL;
}

static kelp_policy_action_t action_from_string(const char *s)
{
    if (!s) return KELP_POLICY_ALLOW;

    if (strcmp(s, "allow") == 0)  return KELP_POLICY_ALLOW;
    if (strcmp(s, "deny")  == 0)  return KELP_POLICY_DENY;
    if (strcmp(s, "ask")   == 0)  return KELP_POLICY_ASK;
    if (strcmp(s, "audit") == 0)  return KELP_POLICY_AUDIT;

    return KELP_POLICY_ALLOW;
}

/* ---- public API --------------------------------------------------------- */

kelp_policy_t *kelp_policy_new(void)
{
    kelp_policy_t *p = calloc(1, sizeof(*p));
    return p;
}

void kelp_policy_free(kelp_policy_t *p)
{
    if (!p)
        return;

    for (size_t i = 0; i < p->count; i++)
        rule_free(&p->rules[i]);

    free(p->rules);
    free(p);
}

int kelp_policy_load(kelp_policy_t *p, const char *path)
{
    if (!p || !path)
        return -1;

    cJSON *root = kelp_json_parse_file(path);
    if (!root) {
        KELP_ERROR("policy: failed to parse policy file: %s", path);
        return -1;
    }

    if (!cJSON_IsArray(root)) {
        KELP_ERROR("policy: expected JSON array in: %s", path);
        cJSON_Delete(root);
        return -1;
    }

    int loaded = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, root) {
        if (!cJSON_IsObject(item))
            continue;

        const char *tool    = kelp_json_get_string(item, "tool");
        const char *pattern = kelp_json_get_string(item, "pattern");
        const char *action  = kelp_json_get_string(item, "action");
        const char *reason  = kelp_json_get_string(item, "reason");

        if (!tool || !pattern || !action) {
            KELP_WARN("policy: skipping incomplete rule in %s", path);
            continue;
        }

        kelp_policy_rule_t rule = {
            .tool_name = tool,
            .pattern   = pattern,
            .action    = action_from_string(action),
            .reason    = reason,
        };

        if (kelp_policy_add_rule(p, &rule) == 0)
            loaded++;
    }

    cJSON_Delete(root);

    KELP_INFO("policy: loaded %d rules from %s", loaded, path);
    return 0;
}

int kelp_policy_add_rule(kelp_policy_t *p, const kelp_policy_rule_t *rule)
{
    if (!p || !rule)
        return -1;

    if (p->count >= p->cap) {
        if (policy_grow(p) != 0)
            return -1;
    }

    rule_t *r = &p->rules[p->count];
    r->tool_name = safe_strdup(rule->tool_name);
    r->pattern   = safe_strdup(rule->pattern);
    r->action    = rule->action;
    r->reason    = safe_strdup(rule->reason);

    /* If any critical allocation failed, roll back. */
    if ((rule->tool_name && !r->tool_name) ||
        (rule->pattern   && !r->pattern)) {
        rule_free(r);
        return -1;
    }

    p->count++;
    return 0;
}

kelp_policy_action_t kelp_policy_check(const kelp_policy_t *p,
                                         const char *tool,
                                         const char *arg)
{
    if (!p || !tool)
        return KELP_POLICY_ALLOW;

    const char *check_arg = arg ? arg : "";

    for (size_t i = 0; i < p->count; i++) {
        const rule_t *r = &p->rules[i];

        /* Match tool name: "*" matches any tool, otherwise exact match. */
        bool tool_match = false;
        if (r->tool_name) {
            if (strcmp(r->tool_name, "*") == 0)
                tool_match = true;
            else if (strcmp(r->tool_name, tool) == 0)
                tool_match = true;
        }

        if (!tool_match)
            continue;

        /* Match argument against glob pattern. */
        bool arg_match = false;
        if (!r->pattern || strcmp(r->pattern, "*") == 0) {
            arg_match = true;
        } else {
            if (fnmatch(r->pattern, check_arg, FNM_PATHNAME) == 0)
                arg_match = true;
            /* Also try matching just the basename for file paths. */
            const char *basename = strrchr(check_arg, '/');
            if (basename) {
                basename++;
                if (fnmatch(r->pattern, basename, 0) == 0)
                    arg_match = true;
            }
        }

        if (arg_match)
            return r->action;
    }

    /* No matching rule -- default to allow. */
    return KELP_POLICY_ALLOW;
}

void kelp_policy_add_default_rules(kelp_policy_t *p)
{
    if (!p)
        return;

    /* ---- Destructive commands ---- */

    static const kelp_policy_rule_t defaults[] = {
        /* Block "rm -rf /" and variants. */
        { "bash", "rm -rf /*",    KELP_POLICY_DENY,
          "recursive deletion of root filesystem" },
        { "bash", "rm -rf /",     KELP_POLICY_DENY,
          "recursive deletion of root filesystem" },
        { "bash", "rm -fr /*",    KELP_POLICY_DENY,
          "recursive deletion of root filesystem" },
        { "bash", "rm -fr /",     KELP_POLICY_DENY,
          "recursive deletion of root filesystem" },

        /* Block mkfs on any device. */
        { "bash", "mkfs*",        KELP_POLICY_DENY,
          "filesystem creation on device" },

        /* Block dd writing to block devices. */
        { "bash", "dd *of=/dev/*", KELP_POLICY_DENY,
          "raw write to block device" },

        /* ---- Protected directories ---- */
        { "file_write", "/etc/*",    KELP_POLICY_DENY,
          "writing to system configuration" },
        { "file_write", "/usr/*",    KELP_POLICY_DENY,
          "writing to system binaries" },
        { "file_write", "/boot/*",   KELP_POLICY_DENY,
          "writing to boot partition" },
        { "file_write", "/sbin/*",   KELP_POLICY_DENY,
          "writing to system binaries" },
        { "file_write", "/lib/*",    KELP_POLICY_DENY,
          "writing to system libraries" },

        /* ---- Sensitive file patterns ---- */
        { "*", "*.env",          KELP_POLICY_DENY,
          "access to environment/secret file" },
        { "*", ".env",           KELP_POLICY_DENY,
          "access to environment/secret file" },
        { "*", "*.pem",          KELP_POLICY_DENY,
          "access to certificate/key file" },
        { "*", "*.key",          KELP_POLICY_DENY,
          "access to private key file" },
        { "*", ".ssh/*",         KELP_POLICY_DENY,
          "access to SSH directory" },
        { "*", "*id_rsa*",       KELP_POLICY_DENY,
          "access to SSH private key" },
        { "*", "*id_ed25519*",   KELP_POLICY_DENY,
          "access to SSH private key" },

        /* ---- Audit all bash exec by default ---- */
        { "bash", "*",          KELP_POLICY_AUDIT,
          "all shell commands are audited" },
    };

    size_t n = sizeof(defaults) / sizeof(defaults[0]);
    for (size_t i = 0; i < n; i++) {
        kelp_policy_add_rule(p, &defaults[i]);
    }

    KELP_INFO("policy: added %zu default rules", n);
}
