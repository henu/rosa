#include "symlink.h"

#include <hpp/cast.h>
#include <hpp/serialize.h>

namespace Nodes
{

Symlink::Symlink(void)
{
}

Symlink::Symlink(Hpp::Path const& path) :
path(path)
{
}

Symlink::Symlink(Hpp::ByteV const& serialized)
{
	Hpp::ByteV::const_iterator serialized_it = serialized.begin();
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
(void)serialized_it;
}

void Symlink::serialize(Hpp::ByteV& result) const
{
// TODO: Code this!
HppAssert(false, "Not implemented yet!");
(void)result;
}

}
