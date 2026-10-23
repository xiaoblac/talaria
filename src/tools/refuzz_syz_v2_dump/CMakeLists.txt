add_executable(refuzz_syz_v2_dump
    main.cpp
)

target_link_libraries(refuzz_syz_v2_dump
    PRIVATE
        refuzz_program_syz_v2
)
