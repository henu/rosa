#ifndef OPTIONS_H
#define OPTIONS_H

#define ARCHIVE_IDENTIFIER ("ROSA")

size_t const SALT_SIZE = 64;
size_t const PASSWORD_VERIFIER_SIZE = 64;
size_t const STATIC_DATABLOCK_SIZE = 1024*1024*4;

// There are not options, but its still best place to put them.
size_t const NODE_HASH_SIZE = 64;
size_t const ROOT_REF_AND_SIZES_SIZE = NODE_HASH_SIZE + 3*8;

#endif
