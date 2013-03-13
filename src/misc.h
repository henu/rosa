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
		
		// Calculate how many bytes are required
		size_t bytes_required = 1;
		while (range > (1 << (bytes_required * 8))) {
			++ bytes_required;
		}
		
		Hpp::ByteV random_bytev = Hpp::randomSecureData(bytes_required);
		HppAssert(random_bytev.size() == bytes_required, "Random get failed!");
		uint64_t random_raw = Hpp::cStrToUInt(&random_bytev[0], bytes_required);
		uint64_t random = (random_raw % range);
		
		return min + random;
	} else {
		return Hpp::randomInt(min, max);
	}
}

#endif
