/*
 * clawd-linux :: libclawd-core
 * err.c - Structured error handling
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/err.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void clawd_err_set(clawd_err_t *e, int code, const char *fmt, ...)
{
    if (!e) return;

    e->code = code;

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->message, sizeof(e->message), fmt, ap);
        va_end(ap);
    } else {
        e->message[0] = '\0';
    }
}

bool clawd_err_ok(const clawd_err_t *e)
{
    return e && e->code == CLAWD_OK;
}

const char *clawd_err_string(int code)
{
    switch (code) {
    case CLAWD_OK:           return "OK";
    case CLAWD_ERR_NOMEM:    return "out of memory";
    case CLAWD_ERR_IO:       return "I/O error";
    case CLAWD_ERR_PARSE:    return "parse error";
    case CLAWD_ERR_NET:      return "network error";
    case CLAWD_ERR_AUTH:     return "authentication error";
    case CLAWD_ERR_TIMEOUT:  return "timeout";
    case CLAWD_ERR_NOTFOUND: return "not found";
    case CLAWD_ERR_INVALID:  return "invalid argument";
    case CLAWD_ERR_INTERNAL: return "internal error";
    default:                 return "unknown error";
    }
}
