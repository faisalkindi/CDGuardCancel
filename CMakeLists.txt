cmake_minimum_required(VERSION 3.20)
project(CDGuardCancel LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(SAFETYHOOK_FETCH_ZYDIS ON)
FetchContent_Declare(safetyhook
    GIT_REPOSITORY https://github.com/cursey/safetyhook.git
    GIT_TAG v0.4.1
)
FetchContent_MakeAvailable(safetyhook)

add_library(CDGuardCancel SHARED src/dllmain.cpp)
target_link_libraries(CDGuardCancel PRIVATE safetyhook xinput)

set_target_properties(CDGuardCancel PROPERTIES
    PREFIX ""
    SUFFIX ".asi"
    OUTPUT_NAME "CDGuardCancel"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
