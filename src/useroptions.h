#ifndef USEROPTIONS_H
#define USEROPTIONS_H

#include <hpp/compressor.h>
#include <ostream>

struct Useroptions
{
	static size_t const DEFAULT_WRITECACHE_SIZE = 320 * 1024;
	static size_t const DEFAULT_READCACHE_SIZE = 64 * 1024 * 1024;

	std::ostream* verbose;

	int compression_level;

	size_t writecache_size;
	size_t readcache_size;

	inline Useroptions(void) :
	verbose(NULL),
	compression_level(Hpp::Compressor::DEFAULT_COMPRESSION),
	writecache_size(DEFAULT_WRITECACHE_SIZE),
	readcache_size(DEFAULT_READCACHE_SIZE)
	{
	}

};

#endif
