# For more information about build system see
# https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/build-system.html
cmake_minimum_required(VERSION 3.16)

# microlink ships as a vendored submodule under external/microlink. Its
# components live at:
#   external/microlink/components/microlink                       (microlink itself)
#   external/microlink/components/microlink/components/wireguard_lwip (the WG-for-lwIP backend)
# The Csontikka/microlink repo also exposes a convenience symlink at
#   external/microlink/components/wireguard_lwip
# but Git on Windows checks symlinks out as plain-text files unless
# Developer Mode is on, so we point ESP-IDF at the real paths instead
# and ignore the symlink. Doing it this way keeps the project building
# on a fresh Windows clone without any setup ritual.
set(EXTRA_COMPONENT_DIRS
    external/microlink/components/microlink
    external/microlink/components/microlink/components/wireguard_lwip
)

# PlatformIO passes an environment-specific generated sdkconfig path. Make the
# tracked defaults explicit as well: otherwise some PlatformIO/CMake cache
# combinations regenerate sdkconfig.<env> from Kconfig defaults (10 sockets)
# and silently discard the network-service budget in sdkconfig.defaults.
set(SDKCONFIG_DEFAULTS "${CMAKE_SOURCE_DIR}/sdkconfig.defaults" CACHE STRING
    "Project sdkconfig defaults" FORCE)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# PROJECT_VER lands in the esp_app_desc_t struct so the running firmware
# can report its version via the OTA APIs and the web UI's Status page.
set(PROJECT_VER "3.1.3")
# The migration bridge (env esp32-s3-bridge, CONFIG_TSR_MIGRATION_BRIDGE) is a
# 2.x-line release so that 2.x updaters install it like any other update.
set(TSR_BRIDGE_VER "2.1.0")
if(DEFINED SDKCONFIG AND EXISTS "${SDKCONFIG}")
    file(STRINGS "${SDKCONFIG}" _tsr_bridge REGEX "^CONFIG_TSR_MIGRATION_BRIDGE=y$")
    if(_tsr_bridge)
        set(PROJECT_VER "${TSR_BRIDGE_VER}")
    endif()
endif()

# Test-only packet-path profiling (docs/PERFORMANCE-EXPLORATION-ROADMAP.md):
# only when the build environment sets TSR_PERF_PROFILE=1. Release builds never
# define it, and such an image reports a version ending in "-prof".
# Test-only placement experiment: TSR_CRYPTO_IN_FLASH=1 keeps the WireGuard
# crypto loops out of IRAM; such an image reports a version with "-flash".
if("$ENV{TSR_CRYPTO_IN_FLASH}" STREQUAL "1")
    idf_build_set_property(COMPILE_DEFINITIONS "TSR_CRYPTO_IN_FLASH=1" APPEND)
    set(PROJECT_VER "${PROJECT_VER}-flash")
endif()
if("$ENV{TSR_PERF_PROFILE}" STREQUAL "1")
    idf_build_set_property(COMPILE_DEFINITIONS "TSR_PERF_PROFILE=1" APPEND)
    set(PROJECT_VER "${PROJECT_VER}-prof")
endif()

# A/B tuning only. Keep the stable setting unless a lab build selects
# another value, and mark the version so it cannot be mistaken for release.
set(_sta_limit "$ENV{TSR_TEST_STA_SHED_FROM}")
if(NOT _sta_limit STREQUAL "")
    if(NOT _sta_limit MATCHES "^(28|32)$")
        message(FATAL_ERROR "TSR_TEST_STA_SHED_FROM must be 28 or 32")
    endif()
    idf_build_set_property(COMPILE_DEFINITIONS "STA_SHED_FROM=${_sta_limit}" APPEND)
    set(PROJECT_VER "${PROJECT_VER}-q${_sta_limit}")
endif()

project(esp32_tsr)

if(CONFIG_LWIP_IPV4_NAPT OR CONFIG_LWIP_DHCPS)
    idf_component_get_property(_lwip_dir lwip COMPONENT_DIR)
    idf_component_get_property(_lwip_lib lwip COMPONENT_LIB)
    idf_build_get_property(_idf_python PYTHON)
    set(_napt_patch "${CMAKE_CURRENT_SOURCE_DIR}/tools/prepare_lwip_napt.py")
    set(_napt_generated "${CMAKE_CURRENT_BINARY_DIR}/lwip-napt")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${_napt_patch}"
        "${_lwip_dir}/lwip/src/core/ipv4/ip4_napt.c"
        "${_lwip_dir}/lwip/src/core/timeouts.c")
    execute_process(
        COMMAND "${_idf_python}" "${_napt_patch}" "${_lwip_dir}/lwip" "${_napt_generated}"
        RESULT_VARIABLE _napt_result
        ERROR_VARIABLE _napt_error)
    if(NOT _napt_result STREQUAL "0")
        message(FATAL_ERROR "Could not prepare lwIP NAPT: ${_napt_error}")
    endif()
    get_target_property(_lwip_sources ${_lwip_lib} SOURCES)
    list(LENGTH _lwip_sources _lwip_original_count)
    list(FILTER _lwip_sources EXCLUDE REGEX "(^|/)(ip4_napt|timeouts)[.]c$")
    list(LENGTH _lwip_sources _lwip_filtered_count)
    math(EXPR _lwip_removed_count "${_lwip_original_count} - ${_lwip_filtered_count}")
    if(NOT _lwip_removed_count EQUAL 2)
        message(FATAL_ERROR "Could not locate the two pinned lwIP sources to replace")
    endif()
    list(APPEND _lwip_sources "${_napt_generated}/ip4_napt.c" "${_napt_generated}/timeouts.c")
    set_property(TARGET ${_lwip_lib} PROPERTY SOURCES "${_lwip_sources}")
    target_include_directories(${_lwip_lib} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/components/dhcpserver/include")
    if(CONFIG_LWIP_DHCPS)
        idf_component_get_property(_dhcps_lib dhcpserver COMPONENT_LIB)
        target_compile_definitions(${_dhcps_lib} PRIVATE RECOVERYGATEWAY_LWIP_OWNED_TIMEOUTS=1)
    endif()
endif()

# Keep the reviewed task reaper. The upstream external-stack option uses
# vTaskDeleteWithCaps(NULL), which can allocate during self-deletion.
if(CONFIG_MQTT_TASK_STACK_ON_EXTERNAL_MEMORY)
    message(FATAL_ERROR "The project MQTT task reaper requires the upstream external-stack option off")
endif()
idf_component_get_property(_mqtt_component_dir espressif__mqtt COMPONENT_DIR)
file(SHA256 "${_mqtt_component_dir}/mqtt_client.c" _mqtt_source_hash)
if(NOT _mqtt_source_hash STREQUAL "83e5a7065b8774dce83dd6b9be0163caed3a4fdbbd7de38b328e7e01911487dc")
    message(FATAL_ERROR "Unreviewed esp-mqtt source: review task ownership before updating mqtt_task_memory.h adapter")
endif()
idf_component_get_property(_mqtt_component_lib espressif__mqtt COMPONENT_LIB)
target_compile_options(${_mqtt_component_lib} PRIVATE
    "-include${CMAKE_CURRENT_SOURCE_DIR}/main/mqtt_task_memory.h")

# GCC 14 (toolchain-xtensa-esp-elf 14.2.0) throws a false-positive
# -Wmaybe-uninitialized in ESP-IDF's esp_driver_i2c/i2c_master.c
# (ops_current in s_i2c_asynchronous_transaction), which IDF's global
# -Werror then turns into a hard build failure. This project doesn't
# touch that code path; downgrade just this one warning back to
# non-fatal for that component rather than patching the framework.
idf_component_get_property(_i2c_master_lib esp_driver_i2c COMPONENT_LIB)
if(_i2c_master_lib)
    target_compile_options(${_i2c_master_lib} PRIVATE -Wno-error=maybe-uninitialized)
endif()
