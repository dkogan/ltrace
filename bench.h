#pragma once

#include <stdio.h>
#include <stdint.h>
#include <time.h>

static inline uint64_t bench_checkpoint()
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
	return tp.tv_sec * (uint64_t)1e9 + tp.tv_nsec;
}
// to time a function call "f(a,b,c)", change it to "BENCH(f,a,b,c)". This uses
// __auto_type, so gcc-4.9 or higher is required
#define BENCH( name, args... )                                          \
    ({                                                                  \
        uint64_t t0 = bench_checkpoint();				\
        __auto_type res = name(args);                                   \
        uint64_t t1 = bench_checkpoint();				\
        fprintf(stderr, #name " took %g ns\n", (double)(t1-t0));	\
        res;                                                            \
    })
#define BENCH_VOID( name, args... )                                     \
    ({                                                                  \
        uint64_t t0 = bench_checkpoint();				\
        name(args);                                                     \
        uint64_t t1 = rdtscll();                                        \
        fprintf(stderr, #name " took %g ns\n", (double)(t1-t0));	\
        1;                                                              \
    })
