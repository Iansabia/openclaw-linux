/*
 * kelp-linux :: libkelp-security
 * timing.c - Timing-safe comparison implementation
 *
 * Constant-time memory comparison using XOR accumulation.  The volatile
 * qualifier on the accumulator prevents the compiler from optimising
 * the loop into a short-circuit branch.
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/timing.h>

#include <stdint.h>
#include <stddef.h>

bool kelp_timing_safe_cmp(const void *a, const void *b, size_t len)
{
    /*
     * If both pointers are NULL and len is 0, that is a vacuous equality --
     * two empty regions are trivially identical.  If only one is NULL with
     * len 0, return false: one region exists and the other does not.
     * If either pointer is NULL with len > 0, return false immediately --
     * there is no secret data to leak via timing in the NULL case.
     */
    if (!a || !b)
        return (len == 0 && a == b);

    const volatile unsigned char *pa = (const volatile unsigned char *)a;
    const volatile unsigned char *pb = (const volatile unsigned char *)b;

    volatile unsigned char acc = 0;

    for (size_t i = 0; i < len; i++)
        acc |= pa[i] ^ pb[i];

    return acc == 0;
}
