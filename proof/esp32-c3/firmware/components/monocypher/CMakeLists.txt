set(MONOCYPHER_VERSION "4.0.3")
set(MONOCYPHER_ARCHIVE "${CMAKE_BINARY_DIR}/monocypher-${MONOCYPHER_VERSION}.tar.gz")
set(MONOCYPHER_DIR "${CMAKE_BINARY_DIR}/monocypher-${MONOCYPHER_VERSION}")
set(MONOCYPHER_SHA512 "40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965")

if(NOT EXISTS "${MONOCYPHER_DIR}/src/monocypher.c")
  file(DOWNLOAD
    "https://monocypher.org/download/monocypher-${MONOCYPHER_VERSION}.tar.gz"
    "${MONOCYPHER_ARCHIVE}"
    EXPECTED_HASH "SHA512=${MONOCYPHER_SHA512}"
    TLS_VERIFY ON
    STATUS download_status
  )
  list(GET download_status 0 download_code)
  list(GET download_status 1 download_message)
  if(NOT download_code EQUAL 0)
    message(FATAL_ERROR "Monocypher download failed: ${download_message}")
  endif()
  file(ARCHIVE_EXTRACT INPUT "${MONOCYPHER_ARCHIVE}" DESTINATION "${CMAKE_BINARY_DIR}")
endif()

idf_component_register(
  SRCS
    "${MONOCYPHER_DIR}/src/monocypher.c"
    "${MONOCYPHER_DIR}/src/optional/monocypher-ed25519.c"
  INCLUDE_DIRS
    "${MONOCYPHER_DIR}/src"
    "${MONOCYPHER_DIR}/src/optional"
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)
