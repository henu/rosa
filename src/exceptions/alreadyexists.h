#ifndef EXCEPTIONS_ALREADYEXISTS_H
#define EXCEPTIONS_ALREADYEXISTS_H

#include <hpp/exception.h>

namespace Exceptions
{

class AlreadyExists : public Hpp::Exception
{
public:
	inline AlreadyExists(void);
	inline AlreadyExists(std::string const& error);
};

inline AlreadyExists::AlreadyExists(void)
{
}

inline AlreadyExists::AlreadyExists(std::string const& error) :
Hpp::Exception(error)
{
}

}

#endif
