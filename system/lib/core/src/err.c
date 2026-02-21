/*
 * kelp-linux :: libkelp-core
 * err.c - Structured error handling
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/err.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void kelp_err_set(kelp_err_t *e, int code, const char *fmt, ...)
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

bool kelp_err_ok(const kelp_err_t *e)
{
    return e && e->code == KELP_OK;
}

const char *kelp_err_string(int code)
{
    switch (code) {
    case KELP_OK:           return "OK";
    case KELP_ERR_NOMEM:    return "out of memory";
    case KELP_ERR_IO:       return "I/O error";
    case KELP_ERR_PARSE:    return "parse error";
    case KELP_ERR_NET:      return "network error";
    case KELP_ERR_AUTH:     return "authentication error";
    case KELP_ERR_TIMEOUT:  return "timeout";
    case KELP_ERR_NOTFOUND: return "not found";
    case KELP_ERR_INVALID:  return "invalid argument";
    case KELP_ERR_INTERNAL: return "internal error";
    default:                 return "unknown error";
    }
}
