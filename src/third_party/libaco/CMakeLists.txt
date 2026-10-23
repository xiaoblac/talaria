# Vendored libaco — https://github.com/hnes/libaco (Apache-2.0).
# Pinned: commit d00631a9e143a8711c0a6e7b603a72b1e379b661 (v1.2.4).
#
# Ultra-light stackful-coroutine primitive: one shared run-stack + a per-co
# copy-stack that grows to the coroutine's actual suspend depth. refuzz_control
# uses it to run every Job as a coroutine on a single OS thread instead of one
# OS thread per Job (see control/src/job/job.cpp).
#
# acosw.S is preprocessed x86-64/aarch64 context-switch assembly, so we need the
# ASM language enabled for this target.
enable_language(ASM)

add_library(aco STATIC
    aco.c
    acosw.S
)

target_include_directories(aco PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# libaco cooperatively multiplexes coroutines onto the calling thread; it links
# nothing extra. If the rest of the project is built with AddressSanitizer,
# define ACO_USE_ASAN so libaco annotates its stack switches (avoids false
# positives from ASan's fake-stack across context switches).
if(CMAKE_CXX_FLAGS MATCHES "-fsanitize=address" OR CMAKE_C_FLAGS MATCHES "-fsanitize=address")
    target_compile_definitions(aco PRIVATE ACO_USE_ASAN)
endif()
