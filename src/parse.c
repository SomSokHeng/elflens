#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elflens.h"

static uint32_t rd16(const unsigned char *p, int le)
{
    return le ? (uint32_t)(p[0] | (p[1] << 8)) : (uint32_t)(p[0] << 8 | p[1]);
}

static uint32_t rd32(const unsigned char *p, int le)
{
    if (le)
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t rd64(const unsigned char *p, int le)
{
    if (le)
        return (uint64_t)rd32(p, 1) | ((uint64_t)rd32(p + 4, 1) << 32);
    return ((uint64_t)rd32(p, 0) << 32) | (uint64_t)rd32(p + 4, 0);
}

double inf_entropy(const unsigned char *b, size_t n, size_t step)
{
    size_t cnt[256] = {0};
    size_t tot = 0;
    size_t i;
    if (!b || n == 0)
        return 0.0;
    for (i = 0; i < n; i += (step ? step : 1)) {
        cnt[b[i]]++;
        tot++;
    }
    if (!tot)
        return 0.0;
    double h = 0.0;
    for (i = 0; i < 256; i++) {
        if (cnt[i]) {
            double p = (double)cnt[i] / (double)tot;
            h -= p * log2(p);
        }
    }
    return h;
}

int inf_is_printable_run(const unsigned char *b, size_t n, size_t minlen)
{
    size_t i;
    if (n < minlen)
        return 0;
    for (i = 0; i < n; i++) {
        if (b[i] < 0x20 || b[i] > 0x7e)
            return 0;
    }
    return 1;
}

int vso_read_all(const char *path, unsigned char **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz <= 0 || sz > (1L << 31)) {
        fclose(f);
        return -1;
    }
    rewind(f);
    unsigned char *b = malloc((size_t)sz + 1);
    if (!b) {
        fclose(f);
        return -1;
    }
    size_t got = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(b);
        return -1;
    }
    b[sz] = 0;
    *buf = b;
    *len = (size_t)sz;
    return 0;
}

int vso_detect(const unsigned char *b, size_t n, fmt_t *k, int *bits, int *le)
{
    if (n >= 64 && !memcmp(b, "\x7f" "ELF", 4)) {
        *k = FMT_ELF;
        *bits = (b[4] == 2) ? 64 : 32;
        *le = (b[5] == 1);
        return 0;
    }
    if (n >= 0x40 && b[0] == 'M' && b[1] == 'Z') {
        *k = FMT_PE;
        *le = 1;
        return 0;
    }
    if (n >= 8) {
        uint32_t mg = rd32(b, 1);
        if (mg == 0xFEEDFACE || mg == 0xCEFAEDFE || mg == 0xFEEDFACF || mg == 0xCFFAEDFE) {
            *k = FMT_MACHO;
            *bits = (mg == 0xFEEDFACF || mg == 0xCFFAEDFE) ? 64 : 32;
            *le = (mg == 0xFEEDFACE || mg == 0xFEEDFACF);
            return 0;
        }
    }
    *k = FMT_UNKNOWN;
    return -1;
}

static const char *mach_name(uint32_t m)
{
    switch (m) {
    case 3: return "x86";
    case 7: return "x86_64";
    case 40: return "arm";
    case 62: return "x86_64";
    case 167: return "arm64";
    case 0x01000007: return "x86_64";
    default: return "unknown";
    }
}

int inf_pie(const char *interp, uint32_t type, int is_dyn)
{
    (void)interp;
    (void)is_dyn;
    return type == 3;
}

int vso_elf(unsigned char *b, size_t n, info_t *o)
{
    int is64 = (b[4] == 2);
    int le = (b[5] == 1);
    uint16_t type = rd16(b + 16, le);
    uint16_t machine = rd16(b + 18, le);
    uint32_t shoff;
    uint16_t shentsize, shnum, shstrndx;
    uint64_t entry;

    o->type = type;
    o->machine = machine;
    o->is_le = le;
    snprintf(o->fmt, sizeof(o->fmt), "ELF%d", is64 ? 64 : 32);
    o->stripped = 1;

    if (is64) {
        entry = rd64(b + 24, le);
        shoff = rd64(b + 40, le);
        shentsize = rd16(b + 58, le);
        shnum = rd16(b + 60, le);
        shstrndx = rd16(b + 62, le);
    } else {
        entry = rd32(b + 24, le);
        shoff = rd32(b + 32, le);
        shentsize = rd16(b + 46, le);
        shnum = rd16(b + 48, le);
        shstrndx = rd16(b + 50, le);
    }
    o->entry = entry;
    o->nsec = shnum;
    o->bits = is64 ? 64 : 32;

    if (!shoff || !shnum)
        return 0;
    if ((size_t)shoff + (size_t)shnum * shentsize > n)
        return 0;
    if (shstrndx >= shnum)
        return 0;

    unsigned char *shstr = b + shoff + (size_t)shstrndx * shentsize;
    uint64_t stroff = is64 ? rd64(shstr + 24, le) : rd32(shstr + 16, le);
    uint64_t strsz = is64 ? rd64(shstr + 32, le) : rd32(shstr + 20, le);
    if (stroff + strsz > n)
        return 0;
    const char *shstrtab = (const char *)(b + stroff);

    uint32_t dynstr_off = 0;
    uint32_t got_nx = 0, bss_prot = 0, relro = 0;
    uint64_t rel_addr = 0, rel_sz = 0;
    uint32_t needed_off[VSO_ENT_MAX];
    int n_needed = 0;

    for (uint16_t i = 0; i < shnum && i < VSO_ENT_MAX; i++) {
        unsigned char *sh = b + shoff + (size_t)i * shentsize;
        uint32_t nameoff = rd32(sh, le);
        uint32_t shtype = rd32(sh + 4, le);
        uint64_t flags, addr, off, size;
        if (is64) {
            flags = rd64(sh + 8, le);
            addr = rd64(sh + 16, le);
            off = rd64(sh + 24, le);
            size = rd64(sh + 32, le);
        } else {
            flags = rd32(sh + 8, le);
            addr = rd32(sh + 12, le);
            off = rd32(sh + 16, le);
            size = rd32(sh + 20, le);
        }
        const char *nm = "??";
        if (stroff + nameoff < n)
            nm = shstrtab + nameoff;
        if (nm && *nm && !nm[0]) {
            snprintf(o->sec_name[i], 32, "%s", "?");
        } else {
            snprintf(o->sec_name[i], 32, "%s", nm ? nm : "?");
        }
        o->sec_size[i] = size;

        if (shtype == 2) {
            o->stripped = 0;
            o->nsym = size / (is64 ? 24 : 16);
        } else if (shtype == 11) {
            o->nsec = o->nsec;
        } else if (shtype == 3 && strstr(nm ? nm : "", ".dynstr")) {
            dynstr_off = (uint32_t)off;
        } else if (shtype == 3 && strstr(nm ? nm : "", ".shstrtab")) {
        } else if (shtype == 1 && nm && !strcmp(nm, ".interp")) {
            if (off + size <= n && size > 0) {
                size_t lim = size;
                if (lim > sizeof(o->interp) - 1)
                    lim = sizeof(o->interp) - 1;
                memcpy(o->interp, b + off, lim);
                o->interp[lim] = 0;
                char *z = o->interp;
                size_t k = 0;
                while (k < lim && z[k] && z[k] >= 0x20 && z[k] <= 0x7e)
                    k++;
                z[k] = 0;
            }
        } else if (shtype == 6) {
            const unsigned char *d = b + off;
            uint64_t dsz = size;
            if (off + size <= n) {
                uint16_t step = is64 ? 16 : 8;
                for (uint64_t k = 0; k + step <= dsz; k += step) {
                    uint64_t tag = is64 ? rd64(d + k, le) : rd32(d + k, le);
                    uint64_t val = is64 ? rd64(d + k + 8, le) : rd32(d + k + 4, le);
                    if (!tag)
                        break;
                    if (tag == 1 && n_needed < VSO_ENT_MAX)
                        needed_off[n_needed++] = (uint32_t)val;                    else if (tag == 0x6ffffffb)
                        got_nx = 1;
                    else if (tag == 0x6ffffffa)
                        bss_prot = 1;
                    else if (tag == 0x6ffffff9)
                        relro = 1;
                }
            }
        } else if (shtype == 4) {
            rel_addr = addr;
            rel_sz = size;
        }
        (void)flags;
        (void)addr;

        if (shtype != 8 && off + size <= n && size > 0 && off < n) {
            o->sec_entropy[i] = inf_entropy(b + off, (size_t)size, 0);
        }
    }

    o->has_nx = got_nx ? 1 : 0;
    o->has_relro = relro ? 1 : 0;
    o->has_pie = inf_pie(o->interp, type, type == 3);
    o->static_link = (o->interp[0] == 0) && !dynstr_off;
    o->nlib = 0;
    (void)bss_prot;
    (void)rel_addr;
    (void)rel_sz;

    if (dynstr_off && dynstr_off < n) {
        for (int i = 0; i < n_needed; i++) {
            size_t so = dynstr_off + needed_off[i];
            if (so >= n)
                continue;
            size_t lim = n - so;
            if (lim > INF_PATH_MAX - 1)
                lim = INF_PATH_MAX - 1;
            char tmp[INF_PATH_MAX];
            memcpy(tmp, b + so, lim);
            tmp[lim] = 0;
            if (!tmp[0])
                continue;
            if (o->nlib_keep < VSO_ENT_MAX) {
                o->libs[o->nlib_keep++] = strdup(tmp);
                o->nlib++;
            }
        }
    }

    for (uint16_t i = 0; i < shnum && i < VSO_ENT_MAX; i++) {
        unsigned char *sh = b + shoff + (size_t)i * shentsize;
        uint32_t shtype = rd32(sh + 4, le);
        if (shtype == 2 || shtype == 11) {
            uint64_t off = is64 ? rd64(sh + 24, le) : rd32(sh + 16, le);
            uint64_t size = is64 ? rd64(sh + 32, le) : rd32(sh + 20, le);
            uint32_t link = rd32(sh + (is64 ? 40 : 24), le);
            uint64_t esz = is64 ? 24 : 16;
            if (link < shnum) {
                unsigned char *lsh = b + shoff + (size_t)link * shentsize;
                uint64_t soff = is64 ? rd64(lsh + 24, le) : rd32(lsh + 16, le);
                if (soff < n && off + size <= n) {
                    const char *st = (const char *)(b + soff);
                    uint64_t k;
                    for (k = 0; k + esz <= size; k += esz) {
                        uint32_t nm = rd32(b + off + k, le);
                        if (nm && soff + nm < n) {
                            const char *sn = st + nm;
                            if (*sn && o->nsym_keep < VSO_ENT_MAX)
                                o->syms[o->nsym_keep++] = strdup(sn);
                        }
                    }
                }
            }
        }
    }

    o->has_canary = 0;
    for (int i = 0; i < o->nsym_keep; i++) {
        if (o->syms[i] && strstr(o->syms[i], "__stack_chk_fail"))
            o->has_canary = 1;
    }
    o->nsec = shnum;
    return 0;
}

int vso_pe(unsigned char *b, size_t n, info_t *o)
{
    if (n < 0x40)
        return -1;
    uint32_t peoff = rd32(b + 0x3c, 1);
    if (peoff + 24 > n)
        return -1;
    if (memcmp(b + peoff, "PE\0\0", 4))
        return -1;
    uint16_t machine = rd16(b + peoff + 4, 1);
    uint16_t nsec = rd16(b + peoff + 6, 1);
    uint16_t optsz = rd16(b + peoff + 20, 1);
    uint32_t chars = rd16(b + peoff + 22, 1);
    uint16_t optmagic = rd16(b + peoff + 24, 1);
    int is64 = (optmagic == 0x20b);

    snprintf(o->fmt, sizeof(o->fmt), "PE");
    o->bits = is64 ? 64 : 32;
    o->machine = machine;
    o->is_le = 1;
    o->nsec = nsec;
    o->type = is64 ? 3 : 2;
    o->has_nx = (chars & 0x0100) ? 1 : 0;
    o->has_canary = (chars & 0x4000) ? 1 : 0;
    o->has_relro = 0;
    o->has_pie = (chars & 0x0020) ? 1 : 0;
    o->static_link = 0;

    uint32_t secs = peoff + 24 + optsz;
    for (uint16_t i = 0; i < nsec && i < VSO_ENT_MAX; i++) {
        unsigned char *sh = b + secs + (size_t)i * 40;
        if (sh + 40 > b + n)
            break;
        char nm[9] = {0};
        memcpy(nm, sh, 8);
        size_t vsize = rd32(sh + 8, 1);
        uint32_t vaddr = rd32(sh + 12, 1);
        uint32_t rsize = rd32(sh + 16, 1);
        uint32_t roff = rd32(sh + 20, 1);
        snprintf(o->sec_name[i], 32, "%s", nm);
        o->sec_size[i] = vsize;
        (void)vaddr;
        if (roff + rsize <= n && rsize > 0)
            o->sec_entropy[i] = inf_entropy(b + roff, rsize, 0);
    }
    o->stripped = 0;
    return 0;
}

int vso_macho(unsigned char *b, size_t n, info_t *o)
{
    if (n < 32)
        return -1;
    uint32_t mg = rd32(b, 1);
    int is64 = (mg == 0xFEEDFACF || mg == 0xCFFAEDFE);
    int le = (mg == 0xFEEDFACE || mg == 0xFEEDFACF);
    uint32_t cputype = rd32(b + 4, le);
    uint32_t ncmds = rd32(b + 16, le);
    uint32_t sizeofcmds = rd32(b + 20, le);

    snprintf(o->fmt, sizeof(o->fmt), "MachO%d", is64 ? 64 : 32);
    o->bits = is64 ? 64 : 32;
    o->is_le = le;
    o->machine = cputype;
    (void)mach_name((uint16_t)cputype);
    o->type = 2;
    o->nsec = 0;
    o->has_nx = 0;
    o->has_canary = 0;
    o->has_relro = 0;
    o->has_pie = 0;
    o->static_link = 0;
    (void)sizeofcmds;

    uint64_t off = is64 ? 32 : 28;
    for (uint32_t i = 0; i < ncmds && off + 8 <= n; i++) {
        uint32_t cmd = rd32(b + off, le);
        uint32_t cmdsize = rd32(b + off + 4, le);
        if (cmdsize == 0)
            break;
        if (cmd == 0x19 && off + 24 <= n) {
            uint64_t soff = is64 ? rd64(b + off + 8, le) : rd32(b + off + 8, le);
            uint32_t nstr = is64 ? rd32(b + off + 4, 0) : rd32(b + off + 4, 0);
            (void)nstr;
            if (soff < n) {
                const char *ns = (const char *)(b + soff);
                if (strlen(ns) < INF_PATH_MAX)
                    snprintf(o->interp, sizeof(o->interp), "%s", ns);
            }
        } else if (cmd == 0xc) {
            o->has_pie = 1;
        } else if (cmd == 0x2d) {
            o->has_nx = 1;
        } else if (cmd == 0x1d) {
            o->has_canary = 1;
        }
        off += cmdsize;
    }
    return 0;
}

int vso_strings(const unsigned char *b, size_t n, info_t *o, int minlen)
{
    size_t i = 0;
    int kept = 0;
    if (minlen < INF_STR_MIN)
        minlen = INF_STR_MIN;
    while (i < n && kept < VSO_ENT_MAX) {
        if (b[i] >= 0x20 && b[i] <= 0x7e) {
            size_t j = i;
            while (j < n && b[j] >= 0x20 && b[j] <= 0x7e)
                j++;
            if (j - i >= (size_t)minlen) {
                char *tmp = malloc(j - i + 1);
                if (tmp) {
                    memcpy(tmp, b + i, j - i);
                    tmp[j - i] = 0;
                    o->strs[kept++] = tmp;
                }
            }
            i = j;
        } else {
            i++;
        }
    }
    o->nstr_keep = kept;
    return kept;
}
