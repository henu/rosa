#include "misc.h"

#include <hpp/sha512hasher.h>

Hpp::ByteV secure_bytes;

size_t secureRandomInt(size_t min, size_t max, bool secure_source)
{
	if (secure_source) {
		size_t range = max - min + 1;
		
		// Calculate how many bytes are required
		size_t bytes_required = 1;
		while (range > (1 << (bytes_required * 8))) {
			++ bytes_required;
		}
		
		// If there are not enough secure bytes, then make some
		Hpp::ByteV new_secure_bytes;
		if (secure_bytes.size() < bytes_required) {
			// Take some secure bytes from the secure
			// random number generator of OS.
			new_secure_bytes = Hpp::randomSecureData(64);
			HppAssert(new_secure_bytes.size() == 64, "Random get failed!");
			new_secure_bytes += secure_bytes;
			secure_bytes.swap(new_secure_bytes);
			// Then lengthen random bytes by using hasher
			for (size_t lengthen = 0; lengthen < 1000; ++ lengthen) {
				Hpp::Sha512Hasher hasher;
				hasher.addData(&secure_bytes[0], 64);
				hasher.getHash(new_secure_bytes);
				HppAssert(new_secure_bytes.size() == 64, "Random lengthen failed!");
				new_secure_bytes += secure_bytes;
				secure_bytes.swap(new_secure_bytes);
			}
		}
		
		uint64_t random_raw = Hpp::cStrToUInt(&secure_bytes[secure_bytes.size() - bytes_required], bytes_required);
		secure_bytes.erase(secure_bytes.end() - bytes_required, secure_bytes.end());
		uint64_t random = (random_raw % range);
		
		return min + random;
	} else {
		return Hpp::randomInt(min, max);
	}
}
