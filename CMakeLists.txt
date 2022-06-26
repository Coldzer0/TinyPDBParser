cmake_minimum_required(VERSION 3.20)
project (TinyPDBParser)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/Build)
# set output directories for all builds (Debug, Release, etc.)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(TinyPDBParser main.cpp Core/PEx86.h Core/PDBParser.h)

# Link needed libs.
target_link_libraries(TinyPDBParser PUBLIC urlmon imagehlp)

# Link statically.
target_link_options(TinyPDBParser PRIVATE -static-libgcc -static-libstdc++ -static -lwinpthread -dynamic)
