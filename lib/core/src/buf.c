/*
 * clawd-linux :: libclawd-core
 * buf.c - Dynamic byte buffer
 *
 * SPDX-License-Identifier: MIT
 */

#include <clawd/buf.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- internal helpers --------------------------------------------------- */

static int buf_grow(clawd_buf_t *b, size_t needed)
{
    if (b->len + needed <= b->cap)
        return 0;

    size_t new_cap = b->cap ? b->cap : 256;
    while (new_cap < b->len + needed)
        new_cap *= 2;

    uint8_t *tmp = realloc(b->data, new_cap);
    if (!tmp)
        return -1;

    b->data = tmp;
    b->cap  = new_cap;
    return 0;
}

/* ---- public API --------------------------------------------------------- */

clawd_buf_t clawd_buf_new(size_t initial_cap)
{
    clawd_buf_t b = {0};
    if (initial_cap == 0)
        initial_cap = 256;

    b.data = malloc(initial_cap);
    if (b.data)
        b.cap = initial_cap;
    return b;
}

void clawd_buf_free(clawd_buf_t *b)
{
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len  = 0;
    b->cap  = 0;
}

int clawd_buf_write(clawd_buf_t *b, const void *data, size_t len)
{
    if (!b || !data || len == 0)
        return 0;

    if (buf_grow(b, len) != 0)
        return -1;

    memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

int clawd_buf_read_file(clawd_buf_t *b, const char *path)
{
    if (!b || !path)
        return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    /* Seek to end to learn the size. */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }

    rewind(fp);

    if (buf_grow(b, (size_t)size) != 0) {
        fclose(fp);
        return -1;
    }

    size_t nread = fread(b->data + b->len, 1, (size_t)size, fp);
    if ((long)nread != size) {
        fclose(fp);
        return -1;
    }

    b->len += nread;
    fclose(fp);
    return 0;
}

int clawd_buf_write_file(const clawd_buf_t *b, const char *path)
{
    if (!b || !path)
        return -1;

    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;

    if (b->len > 0) {
        size_t nw = fwrite(b->data, 1, b->len, fp);
        if (nw != b->len) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

void clawd_buf_reset(clawd_buf_t *b)
{
    if (b)
        b->len = 0;
}
