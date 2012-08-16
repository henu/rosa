#ifndef USEROPTIONS_H
#define USEROPTIONS_H

#include <hpp/compressor.h>
#include <ostream>

struct Useroptions
{
	std::ostream* verbose;

	int compression_level;

	inline Useroptions(void) :
	verbose(NULL),
	compression_level(Hpp::Compressor::DEFAULT_COMPRESSION)
	{
	}

};

#endif
