cmake_minimum_required(VERSION 3.20)
project(CDAnimCancel LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(SAFETYHOOK_FETCH_ZYDIS ON)
FetchContent_Declare(safetyhook
    GIT_REPOSITORY https://github.com/cursey/safetyhook.git
    GIT_TAG v0.4.1
)
FetchContent_MakeAvailable(safetyhook)

add_library(CDAnimCancel SHARED src/dllmain.cpp)
target_link_libraries(CDAnimCancel PRIVATE safetyhook xinput)

set_target_properties(CDAnimCancel PROPERTIES
    PREFIX ""
    SUFFIX ".asi"
    OUTPUT_NAME "CDAnimCancel"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
