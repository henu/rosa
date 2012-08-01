#ifndef NODES_CHILDREN_H
#define NODES_CHILDREN_H

#include "type.h"

#include <hpp/bytev.h>
#include <vector>

namespace Nodes
{

struct Child
{
	Hpp::ByteV hash;
	Type type;

	inline bool operator<(Child const& c) const
	{
		return hash < c.hash;
	}
	inline bool operator==(Child const& c) const
	{
		return hash == c.hash;
	}
};
typedef std::vector< Child > Children;


}

#endif
