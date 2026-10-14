#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elflens.h"

static const char *yn(int v)
{
    return v ? "yes" : "no";
}

static const char *grade(const info_t *o)
{
    int s = 100;
    if (!o->has_nx)
        s -= 25;
    if (!o->has_canary)
        s -= 15;
    if (!o->has_pie)
        s -= 20;
    if (!o->has_relro)
        s -= 10;
    if (o->entropy > 7.2)
        s -= 20;
    if (o->is_le)
        s += 0;
    if (s >= 90)
        return "A";
    if (s >= 75)
        return "B";
    if (s >= 60)
        return "C";
    if (s >= 40)
        return "D";
    return "F";
}

int vso_print(const info_t *o, FILE *f)
{
    fprintf(f, "file      %s\n", o->path);
    fprintf(f, "format    %s %s-endian %d-bit\n", o->fmt, o->is_le ? "little" : "big", o->bits);
    fprintf(f, "size      %llu bytes\n", (unsigned long long)o->size);
    fprintf(f, "entry     0x%llx\n", (unsigned long long)o->entry);
    fprintf(f, "sections  %llu\n", (unsigned long long)o->nsec);
    fprintf(f, "symbols   %llu%s\n", (unsigned long long)o->nsym, o->stripped ? " (stripped)" : "");
    fprintf(f, "entropy   %.3f\n", o->entropy);
    fprintf(f, "buildid   %s\n", o->buildid[0] ? o->buildid : "none");
    fprintf(f, "interp    %s\n", o->interp[0] ? o->interp : "none");
    fprintf(f, "static    %s\n", yn(o->static_link));
    fprintf(f, "hardening nx=%s pie=%s canary=%s relro=%s\n", yn(o->has_nx), yn(o->has_pie),
            yn(o->has_canary), yn(o->has_relro));
    fprintf(f, "sha256    %s\n", o->sha256);
    fprintf(f, "sha1      %s\n", o->sha1);
    fprintf(f, "md5       %s\n", o->md5);
    fprintf(f, "grade     %s\n", grade(o));

    if (o->nlib_keep) {
        fprintf(f, "libs\n");
        for (int i = 0; i < o->nlib_keep; i++)
            fprintf(f, "  %s\n", o->libs[i]);
    }
    if (o->nsec) {
        fprintf(f, "sections\n");
        for (uint64_t i = 0; i < o->nsec && i < VSO_ENT_MAX; i++) {
            if (!o->sec_name[i][0])
                continue;
            fprintf(f, "  %-20s %10llu  H=%.3f\n", o->sec_name[i],
                    (unsigned long long)o->sec_size[i], o->sec_entropy[i]);
        }
    }
    return 0;
}

static void jval(FILE *f, const char *v)
{
    if (!v) {
        fprintf(f, "null");
        return;
    }
    fputc('"', f);
    for (const char *p = v; *p; p++) {
        if (*p == '"' || *p == '\\')
            fprintf(f, "\\%c", *p);
        else if ((unsigned char)*p < 0x20)
            fprintf(f, "\\u%04x", (unsigned char)*p);
        else
            fputc(*p, f);
    }
    fputc('"', f);
}

static void jstr(FILE *f, const char *k, const char *v)
{
    fprintf(f, "\"%s\":", k);
    jval(f, v);
}

int vso_json(const info_t *o, FILE *f)
{
    fprintf(f, "{\n  ");
    jstr(f, "file", o->path);
    fprintf(f, ",\n  ");
    jstr(f, "format", o->fmt);
    fprintf(f, ",\n  \"bits\":%d,\n  \"endian\":\"%s\",\n", o->bits, o->is_le ? "little" : "big");
    fprintf(f, "  \"size\":%llu,\n  ", (unsigned long long)o->size);
    jstr(f, "entry", NULL);
    fprintf(f, ",\n  \"entry_addr\":%llu,\n", (unsigned long long)o->entry);
    fprintf(f, "  \"entropy\":%.4f,\n", o->entropy);
    fprintf(f, "  \"nsec\":%llu,\n  \"nsym\":%llu,\n  \"stripped\":%s,\n",
            (unsigned long long)o->nsec, (unsigned long long)o->nsym, o->stripped ? "true" : "false");
    fprintf(f, "  \"static_link\":%s,\n", o->static_link ? "true" : "false");
    fprintf(f, "  \"hardening\":{\"nx\":%s,\"pie\":%s,\"canary\":%s,\"relro\":%s},\n",
            o->has_nx ? "true" : "false", o->has_pie ? "true" : "false",
            o->has_canary ? "true" : "false", o->has_relro ? "true" : "false");
    fprintf(f, "  ");
    jstr(f, "interp", o->interp[0] ? o->interp : NULL);
    fprintf(f, ",\n  ");
    jstr(f, "buildid", o->buildid[0] ? o->buildid : NULL);
    fprintf(f, ",\n  ");
    jstr(f, "sha256", o->sha256);
    fprintf(f, ",\n  ");
    jstr(f, "sha1", o->sha1);
    fprintf(f, ",\n  ");
    jstr(f, "md5", o->md5);
    fprintf(f, ",\n  \"grade\":\"%s\",\n  \"libs\":[", grade(o));
    for (int i = 0; i < o->nlib_keep; i++) {
        if (i)
            fputc(',', f);
        jval(f, o->libs[i]);
    }
    fprintf(f, "],\n  \"sections\":[");
    int first = 1;
    for (uint64_t i = 0; i < o->nsec && i < VSO_ENT_MAX; i++) {
        if (!o->sec_name[i][0])
            continue;
        if (!first)
            fputc(',', f);
        first = 0;
        fprintf(f, "\n    {\"name\":");
        jval(f, o->sec_name[i]);
        fprintf(f, ",\"size\":%llu,\"entropy\":%.4f}", (unsigned long long)o->sec_size[i],
                o->sec_entropy[i]);
    }
    fprintf(f, "\n  ]\n}\n");
    return 0;
}

void vso_usage(FILE *f)
{
    fprintf(f,
            "elflens %s - static binary format auditor\n"
            "usage: elflens [options] <file>\n"
            "  -j, --json      emit JSON\n"
            "  -s, --strings N  print strings of min length N (default off)\n"
            "  -l, --libs      print linked libraries only\n"
            "  -h, --help      this text\n"
            "  -V, --version   version\n"
            "reads file structure only, never executes or modifies input\n",
            VSO_TOOL_VER);
}
