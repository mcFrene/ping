cmake_minimum_required(VERSION 3.16)

project(Ping2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(Ping2 main.cpp)

include(GNUInstallDirs)
install(TARGETS Ping2
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
if(WIN32)
  target_link_libraries(Ping2 ws2_32)
endif()
