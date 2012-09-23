#ifndef EXCEPTIONS_NOTFOUND_H
#define EXCEPTIONS_NOTFOUND_H

#include <hpp/exception.h>

namespace Exceptions
{

class NotFound : public Hpp::Exception
{
public:
	inline NotFound(void);
	inline NotFound(std::string const& error);
};

inline NotFound::NotFound(void)
{
}

inline NotFound::NotFound(std::string const& error) :
Hpp::Exception(error)
{
}

}

#endif
