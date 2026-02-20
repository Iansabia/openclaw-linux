/*
 * clawd-linux :: libclawd-security
 * policy.h - Tool policy enforcement
 *
 * A rule-based policy engine for controlling which tools (bash, file_write,
 * web_fetch, etc.) are allowed, denied, audited, or require user confirmation.
 * Rules are matched in order; the first matching rule wins.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CLAWD_POLICY_H
#define CLAWD_POLICY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Possible actions when a policy rule matches. */
typedef enum {
    CLAWD_POLICY_ALLOW  = 0,  /* permit the operation                      */
    CLAWD_POLICY_DENY   = 1,  /* block the operation                       */
    CLAWD_POLICY_ASK    = 2,  /* requires user confirmation                */
    CLAWD_POLICY_AUDIT  = 3   /* allow but emit an audit log entry         */
} clawd_policy_action_t;

/**
 * A single policy rule.
 *
 * String fields are NOT copied by clawd_policy_add_rule(); the caller must
 * ensure they remain valid for the lifetime of the policy (or use
 * heap-allocated strings that outlive the policy).
 */
typedef struct clawd_policy_rule {
    const char            *tool_name;  /* "bash", "file_write", etc.        */
    const char            *pattern;    /* glob pattern for the argument     */
    clawd_policy_action_t  action;
    const char            *reason;     /* human-readable justification      */
} clawd_policy_rule_t;

/** Opaque policy handle. */
typedef struct clawd_policy clawd_policy_t;

/**
 * Create a new, empty policy.
 *
 * @return A policy handle, or NULL on allocation failure.
 */
clawd_policy_t *clawd_policy_new(void);

/**
 * Free a policy and all internally-owned memory.
 *
 * @param p  Policy handle (may be NULL).
 */
void clawd_policy_free(clawd_policy_t *p);

/**
 * Load policy rules from a JSON file.
 *
 * The file must contain a JSON array of objects, each with the keys
 * "tool", "pattern", "action" (allow|deny|ask|audit), and optionally
 * "reason".
 *
 * Loaded rules are appended after any existing rules.
 *
 * @param p     Policy handle.
 * @param path  Path to the JSON policy file.
 * @return 0 on success, -1 on error.
 */
int clawd_policy_load(clawd_policy_t *p, const char *path);

/**
 * Append a rule to the policy.
 *
 * Rules are evaluated in the order they were added.  The first matching
 * rule determines the action.
 *
 * @param p     Policy handle.
 * @param rule  The rule to add.
 * @return 0 on success, -1 on error.
 */
int clawd_policy_add_rule(clawd_policy_t *p, const clawd_policy_rule_t *rule);

/**
 * Check a tool invocation against the policy.
 *
 * Iterates through rules in order.  If the tool name matches and the
 * argument matches the glob pattern, returns that rule's action.  If no
 * rule matches, CLAWD_POLICY_ALLOW is returned (open by default).
 *
 * @param p     Policy handle.
 * @param tool  Tool name (e.g. "bash").
 * @param arg   Argument string to match against patterns.
 * @return The action dictated by the first matching rule, or CLAWD_POLICY_ALLOW.
 */
clawd_policy_action_t clawd_policy_check(const clawd_policy_t *p,
                                         const char *tool,
                                         const char *arg);

/**
 * Add a set of sensible default rules to the policy.
 *
 * Defaults include:
 *   - Deny  bash  "rm -rf /"
 *   - Deny  *     writing to /etc/*, /usr/*, /boot/*
 *   - Audit bash  "*"
 *   - Deny  *     accessing *.env, *.pem, *.key, .ssh/*
 *
 * Existing rules are preserved; defaults are appended.
 *
 * @param p  Policy handle.
 */
void clawd_policy_add_default_rules(clawd_policy_t *p);

#ifdef __cplusplus
}
#endif

#endif /* CLAWD_POLICY_H */
