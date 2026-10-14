#ifndef ELFLENS_SHA_H
#define ELFLENS_SHA_H

#include <stddef.h>

void vso_hash(const unsigned char *b, size_t n, char *sha256, char *sha1, char *md5);

#endif
