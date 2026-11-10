cmake_minimum_required(VERSION 3.22.1)

project("root_oplus_ace5")

add_library(
    oplus_native
    SHARED
    src/main/cpp/jni_bridge.cpp
    src/main/cpp/root_stage.cpp
    src/main/cpp/futex_probe.cpp
    src/main/cpp/leak_probe.cpp
    src/main/cpp/page_engine.cpp
    src/main/cpp/pipe_phys.cpp
    src/main/cpp/ks_bridge.c
    src/main/cpp/shell_main.cpp
)

target_include_directories(
        oplus_native
        PRIVATE
        src/main/cpp/include
)

target_compile_definitions(
        oplus_native
        PRIVATE
        SU_NO_MAIN
        GL_EMBEDDED
        OPLUS_ONECLICK
)

target_compile_features(
        oplus_native
        PRIVATE
        cxx_std_20
)

find_library(
    log_lib
    log
)

target_link_libraries(
        oplus_native
        PRIVATE
        ${log_lib}
)

add_executable(
    glshell
    src/main/cpp/shell_main.cpp
    src/main/cpp/root_stage.cpp
    src/main/cpp/futex_probe.cpp
    src/main/cpp/leak_probe.cpp
    src/main/cpp/page_engine.cpp
    src/main/cpp/pipe_phys.cpp
    src/main/cpp/ks_bridge.c
)

target_include_directories(
        glshell
        PRIVATE
        src/main/cpp/include
)

target_compile_definitions(
        glshell
        PRIVATE
        SU_NO_MAIN
)

target_compile_features(
        glshell
        PRIVATE
        cxx_std_20
)

target_link_libraries(
        glshell
        PRIVATE
        ${log_lib}
)

