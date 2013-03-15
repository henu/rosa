#ifndef MISC_H
#define MISC_H

#include <hpp/random.h>
#include <hpp/cast.h>

// Generates random integer using range [min, max].
// Secure source can be used if necessary.
size_t secureRandomInt(size_t min, size_t max, bool secure_source);

#endif
