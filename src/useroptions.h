#ifndef USEROPTIONS_H
#define USEROPTIONS_H

#include <hpp/compressor.h>
#include <ostream>

struct Useroptions
{
	static size_t const DEFAULT_CACHE_SIZE = 64 * 1024 * 1024;

	std::ostream* verbose;

	int compression_level;

	size_t cache_size;

	inline Useroptions(void) :
	verbose(NULL),
	compression_level(Hpp::Compressor::DEFAULT_COMPRESSION),
	cache_size(DEFAULT_CACHE_SIZE)
	{
	}

};

#endif
