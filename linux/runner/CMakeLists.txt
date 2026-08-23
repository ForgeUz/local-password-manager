cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
# v5 E10: desktop_plugin.cc holds the native tray + hotkey MethodChannel code.
add_executable(${BINARY_NAME}
  "main.cc"
  "my_application.cc"
  "desktop_plugin.cc"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

# Apply the standard set of build settings. This can be removed for applications
# that need different build settings.
apply_standard_settings(${BINARY_NAME})

# Add preprocessor definitions for the application ID.
add_definitions(-DAPPLICATION_ID="${APPLICATION_ID}")

# Add dependency libraries. Add any application-specific dependencies here.
target_link_libraries(${BINARY_NAME} PRIVATE flutter)
target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::GTK)

# v5 E10: system tray (ayatana-appindicator3) + global hotkey (X11).
# DEPS.md installs: libayatana-appindicator3-dev libx11-dev libxtst-dev.
find_package(PkgConfig REQUIRED)
pkg_check_modules(APPINDICATOR REQUIRED IMPORTED_TARGET ayatana-appindicator3-0.1)
pkg_check_modules(X11 REQUIRED IMPORTED_TARGET x11)

target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::APPINDICATOR)
target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::X11)

# v5 E19: seccomp deny-list uses raw prctl/BPF from libc; the headers come from
# the kernel headers (linux/filter.h, linux/seccomp.h) present on Mint.

target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")
