#ifndef TYPES_H
#define TYPES_H

#include <map>
#include <vector>
#include <hpp/path.h>
#include <hpp/bytev.h>

typedef std::vector< Hpp::Path > Paths;

typedef std::vector< Hpp::ByteV > ByteVs;

typedef std::map< size_t, size_t > SizeBySize;
typedef std::multimap< size_t, size_t > SizeBySizeMulti;

#endif
