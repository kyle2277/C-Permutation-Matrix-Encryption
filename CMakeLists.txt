cmake_minimum_required(VERSION 3.12)
project(Font_Blanc_C C)

set(CMAKE_C_STANDARD 99)

add_library(Font_Blanc_C fontblanc.c fontblanc.h)
add_executable(test_exec test_main.c fontblanc.c fontblanc.h Dependencies/csparse.c Dependencies/csparse.h Dependencies/st_io.c Dependencies/st_io.h)
target_link_libraries(test_exec m)