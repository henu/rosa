#ifndef USEROPTIONS_H
#define USEROPTIONS_H

#include <ostream>

struct Useroptions
{
	std::ostream* verbose;

	inline Useroptions(void) :
	verbose(NULL)
	{
	}

	inline Useroptions getWithoutVerbose(void) const
	{
		Useroptions result(*this);
		result.verbose = NULL;
		return result;
	}

};

#endif
