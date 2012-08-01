#ifndef NODES_DATAENTRY_H
#define NODES_DATAENTRY_H

#include "children.h"

#include <hpp/cast.h>
#include <hpp/bytev.h>

namespace Nodes
{

struct DataEntry
{
	static size_t const HEADER_SIZE = 4;

	static uint32_t const MASK_DATA = 0x1fffffff;
	static uint32_t const MASK_TYPE = 0x60000000;
	static uint32_t const MASK_EMPTY = 0x80000000;
	static uint32_t const MASK_EMPTY_8 = 0x80;
	static uint32_t const MASK_TYPE_8 = 0x60;

	bool empty;
	Type type;
	uint32_t size;
	Hpp::ByteV data;

	DataEntry(void)
	{
	}
	DataEntry(Hpp::ByteV const& serialized)
	{
		HppAssert(serialized.size() == HEADER_SIZE, "Invalid serialized size!");
		empty = serialized[0] & MASK_EMPTY_8;
		type = Type((serialized[0] & MASK_TYPE_8) >> 5);
		size = Hpp::cStrToUInt32(&serialized[0]) & MASK_DATA;
	}
};

}

#endif
