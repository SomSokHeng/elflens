#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elflens.h"
#include "sha.h"

static void vso_cleanup(info_t *o)
{
    for (int i = 0; i < o->nsym_keep; i++)
        free(o->syms[i]);
    for (int i = 0; i < o->nstr_keep; i++)
        free(o->strs[i]);
    for (int i = 0; i < o->nlib_keep; i++)
        free(o->libs[i]);
    o->nsym_keep = o->nstr_keep = o->nlib_keep = 0;
}

static int vso_buildid(info_t *o, const unsigned char *b, size_t n)
{
    for (size_t i = 0; i + 12 <= n; i++) {
        uint32_t nsz = (uint32_t)b[i] | ((uint32_t)b[i + 1] << 8) |
                       ((uint32_t)b[i + 2] << 16) | ((uint32_t)b[i + 3] << 24);
        uint32_t dsz = (uint32_t)b[i + 4] | ((uint32_t)b[i + 5] << 8) |
                       ((uint32_t)b[i + 6] << 16) | ((uint32_t)b[i + 7] << 24);
        uint32_t typ = (uint32_t)b[i + 8] | ((uint32_t)b[i + 9] << 8) |
                       ((uint32_t)b[i + 10] << 16) | ((uint32_t)b[i + 11] << 24);
        if (nsz == 0 || nsz > 64 || dsz > 512 || typ != 3)
            continue;
        size_t name = i + 12;
        size_t doff = name + ((nsz + 3) & ~3u);
        size_t dend = doff + dsz;
        if (name + nsz > n || dend > n)
            continue;
        if (memcmp(b + name, "GNU", 3))
            continue;
        static const char *t = "0123456789abcdef";
        size_t k = 0, cap = sizeof(o->buildid) - 1;
        for (size_t j = doff; j < dend && k + 1 < cap; j++) {
            o->buildid[k++] = t[b[j] >> 4];
            if (k + 1 < cap)
                o->buildid[k++] = t[b[j] & 15];
        }
        o->buildid[k] = 0;
        if (k)
            return 1;
    }
    o->buildid[0] = 0;
    return 0;
}

int main(int argc, char **argv)
{
    int as_json = 0, show_str = 0, libs_only = 0, minlen = INF_STR_MIN;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            vso_usage(stdout);
            return 0;
        }
        if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("elflens %s\n", VSO_TOOL_VER);
            return 0;
        }
        if (!strcmp(a, "-j") || !strcmp(a, "--json")) {
            as_json = 1;
        } else if (!strcmp(a, "-l") || !strcmp(a, "--libs")) {
            libs_only = 1;
        } else if ((!strcmp(a, "-s") || !strcmp(a, "--strings")) && i + 1 < argc) {
            show_str = 1;
            minlen = atoi(argv[++i]);
            if (minlen < 1)
                minlen = INF_STR_MIN;
        } else if (a[0] == '-' && a[1]) {
            fprintf(stderr, "elflens: unknown option %s\n", a);
            return 2;
        } else {
            path = a;
        }
    }

    if (!path) {
        vso_usage(stderr);
        return 2;
    }

    unsigned char *buf = NULL;
    size_t len = 0;
    if (vso_read_all(path, &buf, &len) != 0) {
        fprintf(stderr, "elflens: cannot read %s\n", path);
        return 1;
    }
    if (len < 16) {
        fprintf(stderr, "elflens: %s too small to identify\n", path);
        free(buf);
        return 1;
    }

    info_t o;
    memset(&o, 0, sizeof(o));
    snprintf(o.path, sizeof(o.path), "%s", path);
    o.size = len;
    o.entropy = inf_entropy(buf, len, 0);
    vso_hash(buf, len, o.sha256, o.sha1, o.md5);
    vso_buildid(&o, buf, len);

    fmt_t kind = FMT_UNKNOWN;
    int bits = 0, le = 1;
    vso_detect(buf, len, &kind, &bits, &le);
    o.kind = kind;
    if (kind == FMT_UNKNOWN) {
        fprintf(stderr, "elflens: %s is not a recognized ELF, PE, or Mach-O file\n", path);
        free(buf);
        return 1;
    }

    int rc = 0;
    if (kind == FMT_ELF)
        rc = vso_elf(buf, len, &o);
    else if (kind == FMT_PE)
        rc = vso_pe(buf, len, &o);
    else
        rc = vso_macho(buf, len, &o);
    if (rc != 0) {
        fprintf(stderr, "elflens: malformed %s structure in %s\n", o.fmt, path);
        free(buf);
        vso_cleanup(&o);
        return 1;
    }

    if (libs_only) {
        for (int i = 0; i < o.nlib_keep; i++)
            printf("%s\n", o.libs[i]);
    } else if (as_json) {
        vso_json(&o, stdout);
    } else {
        vso_print(&o, stdout);
    }

    if (show_str) {
        vso_strings(buf, len, &o, minlen);
        for (int i = 0; i < o.nstr_keep; i++)
            printf("%s\n", o.strs[i]);
    }

    vso_cleanup(&o);
    free(buf);
    return 0;
}
