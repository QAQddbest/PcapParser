# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = D:\CLion\bin\cmake\win\bin\cmake.exe

# The command to remove a file.
RM = D:\CLion\bin\cmake\win\bin\cmake.exe -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = D:\Works\C\PcapParser

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = D:\Works\C\PcapParser\build

# Include any dependencies generated for this target.
include src/CMakeFiles/PcapParser.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/PcapParser.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/PcapParser.dir/flags.make

src/CMakeFiles/PcapParser.dir/main.c.obj: src/CMakeFiles/PcapParser.dir/flags.make
src/CMakeFiles/PcapParser.dir/main.c.obj: src/CMakeFiles/PcapParser.dir/includes_C.rsp
src/CMakeFiles/PcapParser.dir/main.c.obj: ../src/main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\Works\C\PcapParser\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/PcapParser.dir/main.c.obj"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\PcapParser.dir\main.c.obj   -c D:\Works\C\PcapParser\src\main.c

src/CMakeFiles/PcapParser.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/PcapParser.dir/main.c.i"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\Works\C\PcapParser\src\main.c > CMakeFiles\PcapParser.dir\main.c.i

src/CMakeFiles/PcapParser.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/PcapParser.dir/main.c.s"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\Works\C\PcapParser\src\main.c -o CMakeFiles\PcapParser.dir\main.c.s

src/CMakeFiles/PcapParser.dir/pcap.c.obj: src/CMakeFiles/PcapParser.dir/flags.make
src/CMakeFiles/PcapParser.dir/pcap.c.obj: src/CMakeFiles/PcapParser.dir/includes_C.rsp
src/CMakeFiles/PcapParser.dir/pcap.c.obj: ../src/pcap.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\Works\C\PcapParser\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/CMakeFiles/PcapParser.dir/pcap.c.obj"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\PcapParser.dir\pcap.c.obj   -c D:\Works\C\PcapParser\src\pcap.c

src/CMakeFiles/PcapParser.dir/pcap.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/PcapParser.dir/pcap.c.i"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\Works\C\PcapParser\src\pcap.c > CMakeFiles\PcapParser.dir\pcap.c.i

src/CMakeFiles/PcapParser.dir/pcap.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/PcapParser.dir/pcap.c.s"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\Works\C\PcapParser\src\pcap.c -o CMakeFiles\PcapParser.dir\pcap.c.s

src/CMakeFiles/PcapParser.dir/tools.c.obj: src/CMakeFiles/PcapParser.dir/flags.make
src/CMakeFiles/PcapParser.dir/tools.c.obj: src/CMakeFiles/PcapParser.dir/includes_C.rsp
src/CMakeFiles/PcapParser.dir/tools.c.obj: ../src/tools.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\Works\C\PcapParser\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object src/CMakeFiles/PcapParser.dir/tools.c.obj"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\PcapParser.dir\tools.c.obj   -c D:\Works\C\PcapParser\src\tools.c

src/CMakeFiles/PcapParser.dir/tools.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/PcapParser.dir/tools.c.i"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\Works\C\PcapParser\src\tools.c > CMakeFiles\PcapParser.dir\tools.c.i

src/CMakeFiles/PcapParser.dir/tools.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/PcapParser.dir/tools.c.s"
	cd /d D:\Works\C\PcapParser\build\src && D:\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\Works\C\PcapParser\src\tools.c -o CMakeFiles\PcapParser.dir\tools.c.s

# Object files for target PcapParser
PcapParser_OBJECTS = \
"CMakeFiles/PcapParser.dir/main.c.obj" \
"CMakeFiles/PcapParser.dir/pcap.c.obj" \
"CMakeFiles/PcapParser.dir/tools.c.obj"

# External object files for target PcapParser
PcapParser_EXTERNAL_OBJECTS =

src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/main.c.obj
src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/pcap.c.obj
src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/tools.c.obj
src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/build.make
src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/linklibs.rsp
src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/objects1.rsp
src/PcapParser.exe: src/CMakeFiles/PcapParser.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=D:\Works\C\PcapParser\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable PcapParser.exe"
	cd /d D:\Works\C\PcapParser\build\src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\PcapParser.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/PcapParser.dir/build: src/PcapParser.exe

.PHONY : src/CMakeFiles/PcapParser.dir/build

src/CMakeFiles/PcapParser.dir/clean:
	cd /d D:\Works\C\PcapParser\build\src && $(CMAKE_COMMAND) -P CMakeFiles\PcapParser.dir\cmake_clean.cmake
.PHONY : src/CMakeFiles/PcapParser.dir/clean

src/CMakeFiles/PcapParser.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" D:\Works\C\PcapParser D:\Works\C\PcapParser\src D:\Works\C\PcapParser\build D:\Works\C\PcapParser\build\src D:\Works\C\PcapParser\build\src\CMakeFiles\PcapParser.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/PcapParser.dir/depend

