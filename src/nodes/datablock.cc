#include "datablock.h"

namespace Nodes
{

Datablock::Datablock(void)
{
}

Datablock::Datablock(Hpp::ByteV const& serialized) :
data(serialized)
{
}

void Datablock::serialize(Hpp::ByteV& result) const
{
	result = data;
}

}
