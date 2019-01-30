cmake_minimum_required (VERSION 2.6)
project (TCP)

set (TCP_VERSION_MAJOR 1)
set (TCP_VERSION_MINOR 0)
set (TCP_SRC_LIST TCP_Main.cpp TCP_Source.cpp)

configure_file (
  "${PROJECT_SOURCE_DIR}/TCP_Config.h.in"
  "${PROJECT_BINARY_DIR}/TCP_Config.h"
  )

include_directories ("${PROJECT_BINARY_DIR}")

add_executable (TCP ${TCP_SRC_LIST})

install (TARGETS TCP DESTINATION bin)
install (FILES Initialization.ini SaveData.txt DESTINATION bin)

include (InstallRequiredSystemLibraries)
set (CPACK_PACKAGE_VERSION_MAJOR "${TCP_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${TCP_VERSION_MINOR}")
include (CPack)