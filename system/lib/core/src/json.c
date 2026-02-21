/*
 * kelp-linux :: libkelp-core
 * json.c - cJSON convenience wrappers
 *
 * SPDX-License-Identifier: MIT
 */

#include <kelp/json.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

cJSON *kelp_json_parse(const char *text)
{
    if (!text)
        return NULL;
    return cJSON_Parse(text);
}

cJSON *kelp_json_parse_file(const char *path)
{
    if (!path)
        return NULL;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    char *buf = malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)size, fp);
    fclose(fp);
    buf[nread] = '\0';

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    return json;
}

const char *kelp_json_get_string(const cJSON *obj, const char *key)
{
    if (!obj || !key)
        return NULL;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL)
        return NULL;
    return item->valuestring;
}

int kelp_json_get_int(const cJSON *obj, const char *key, int def)
{
    if (!obj || !key)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(item))
        return def;
    return item->valueint;
}

bool kelp_json_get_bool(const cJSON *obj, const char *key, bool def)
{
    if (!obj || !key)
        return def;
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (cJSON_IsTrue(item))
        return true;
    if (cJSON_IsFalse(item))
        return false;
    return def;
}

cJSON *kelp_json_get_array(const cJSON *obj, const char *key)
{
    if (!obj || !key)
        return NULL;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsArray(item))
        return NULL;
    return item;
}

cJSON *kelp_json_get_object(const cJSON *obj, const char *key)
{
    if (!obj || !key)
        return NULL;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsObject(item))
        return NULL;
    return item;
}

char *kelp_json_stringify(const cJSON *obj)
{
    if (!obj)
        return NULL;
    return cJSON_PrintUnformatted(obj);
}

char *kelp_json_stringify_pretty(const cJSON *obj)
{
    if (!obj)
        return NULL;
    return cJSON_Print(obj);
}
