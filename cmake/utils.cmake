add_custom_target("uninstall" COMMENT "Remove installed files")

add_custom_command(
  TARGET "uninstall"
  POST_BUILD
  COMMAND xargs rm -vf < install_manifest.txt
  COMMAND [ ! -z \"${CMAKE_INSTALL_PREFIX}\" ] && find
          "${CMAKE_INSTALL_PREFIX}" -empty -type d -delete || true)
