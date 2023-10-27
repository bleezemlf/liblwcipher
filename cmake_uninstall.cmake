# uninstall.cmake

if (EXISTS "${CMAKE_BINARY_DIR}/install_manifest.txt")
    file(READ "${CMAKE_BINARY_DIR}/install_manifest.txt" files)
    string(REGEX REPLACE "\n" ";" files "${files}")
    foreach (file ${files})
        message("Removing file: ${file}")
        file(REMOVE "${file}")
    endforeach()
endif()
