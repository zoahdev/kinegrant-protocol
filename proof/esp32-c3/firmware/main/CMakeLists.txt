idf_component_register(
  SRCS "kgp_firmware.c"
  INCLUDE_DIRS "."
  REQUIRES cjson driver esp_timer nvs_flash bootloader_support mbedtls monocypher
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
