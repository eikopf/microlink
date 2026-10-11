cmake_minimum_required(VERSION 3.16)

# Add microlink component path
set(EXTRA_COMPONENT_DIRS
    "../../components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(microlink_cellular_connect)
