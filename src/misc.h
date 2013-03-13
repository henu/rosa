#ifndef MISC_H
#define MISC_H

#include <hpp/random.h>
#include <hpp/cast.h>

// Generates random integer using range [min, max].
// Secure source can be used if necessary.
inline size_t secureRandomInt(size_t min, size_t max, bool secure_source)
{
	if (secure_source) {
		size_t range = max - min + 1;
		
		Hpp::ByteV random_bytev = Hpp::randomSecureData(8);
		HppAssert(random_bytev.size() == 8, "Random get failed!");
		uint64_t random_raw = Hpp::cStrToUInt64(&random_bytev[0]);
		uint64_t random = (random_raw % range);
		
		return min + random;
	} else {
		return Hpp::randomInt(min, max);
	}
}

#endif
