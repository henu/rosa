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
	path = Hpp::Path(Hpp::deserializeString(serialized_it, serialized.end(), 2));
}

void Symlink::serialize(Hpp::ByteV& result) const
{
	Hpp::serializeString(result, path.toString(true), 2);
}

}
