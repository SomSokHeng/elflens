#ifndef ELFLENS_H
#define ELFLENS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VSO_MAGIC_MAX 8
#define VSO_ENT_MAX 4096
#define INF_PATH_MAX 4096
#define INF_STR_MIN 6
#define INF_HASH_LEN 64
#define VSO_TOOL_VER "1.0.0"

typedef enum {
    FMT_UNKNOWN = 0,
    FMT_ELF,
    FMT_PE,
    FMT_MACHO
} fmt_t;

typedef struct {
    char path[INF_PATH_MAX];
    char fmt[16];
    fmt_t kind;
    int bits;
    int is_le;
    int stripped;
    int static_link;
    int has_nx;
    int has_pie;
    int has_canary;
    int has_relro;
    int signed_bin;
    uint64_t size;
    uint64_t entry;
    uint64_t nsec;
    uint64_t nsym;
    uint64_t nlib;
    uint32_t machine;
    uint32_t type;
    double entropy;
    double sec_entropy[VSO_ENT_MAX];
    char sec_name[VSO_ENT_MAX][32];
    uint64_t sec_size[VSO_ENT_MAX];
    char buildid[80];
    char interp[INF_PATH_MAX];
    char sha256[INF_HASH_LEN + 1];
    char sha1[41];
    char md5[33];
    char *syms[VSO_ENT_MAX];
    int nsym_keep;
    char *strs[VSO_ENT_MAX];
    int nstr_keep;
    char *libs[VSO_ENT_MAX];
    int nlib_keep;
} info_t;

int vso_read_all(const char *path, unsigned char **buf, size_t *len);
int vso_detect(const unsigned char *b, size_t n, fmt_t *k, int *bits, int *le);
int vso_elf(unsigned char *b, size_t n, info_t *o);
int vso_pe(unsigned char *b, size_t n, info_t *o);
int vso_macho(unsigned char *b, size_t n, info_t *o);
double inf_entropy(const unsigned char *b, size_t n, size_t step);
void vso_hash(const unsigned char *b, size_t n, char *sha256, char *sha1, char *md5);
int inf_pie(const char *interp, uint32_t type, int is_dyn);
int vso_strings(const unsigned char *b, size_t n, info_t *o, int minlen);
int vso_print(const info_t *o, FILE *f);
int vso_json(const info_t *o, FILE *f);
void vso_usage(FILE *f);
int inf_is_printable_run(const unsigned char *b, size_t n, size_t minlen);

#endif
