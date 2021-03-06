#ifndef TYPES_H
#define TYPES_H

#include <map>
#include <vector>
#include <set>
#include <hpp/path.h>
#include <hpp/bytev.h>

typedef std::vector< Hpp::Path > Paths;

typedef std::vector< Hpp::ByteV > ByteVs;
typedef std::set< Hpp::ByteV > ByteVSet;

typedef std::map< size_t, size_t > SizeBySize;
typedef std::multimap< size_t, size_t > SizeBySizeMulti;

typedef std::map< uint64_t, uint64_t > UI64ByUI64;

#endif
