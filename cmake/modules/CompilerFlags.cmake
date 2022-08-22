option(BUILD_WARNINGS_AS_ERRORS "Enable building with -Wextra -Werror flags")

option(ENABLE_PIC "Build position independent libraries and executables" OFF)
if(ENABLE_PIC)
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# NOTE: do not add `add_definition` in this file because consumers project won't import it.

if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
	set(CMD_MAKE gmake)
else()
	set(CMD_MAKE make)
endif()

if(NOT MSVC)

	set(FALCOSECURITY_LIBS_COMMON_FLAGS "-Wall -ggdb")
	set(FALCOSECURITY_LIBS_DEBUG_FLAGS "-D_DEBUG")
	set(FALCOSECURITY_LIBS_RELEASE_FLAGS "-O3 -fno-strict-aliasing -DNDEBUG")

	if(MINIMAL_BUILD)
	  set(FALCOSECURITY_LIBS_COMMON_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS} -DMINIMAL_BUILD")
	endif()

	if(MUSL_OPTIMIZED_BUILD)
		set(FALCOSECURITY_LIBS_COMMON_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS} -static -Os")
	endif()

	if(BUILD_WARNINGS_AS_ERRORS)
		set(CMAKE_SUPPRESSED_WARNINGS "-Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wno-type-limits -Wno-implicit-fallthrough -Wno-format-truncation")
		set(FALCOSECURITY_LIBS_COMMON_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS} -Wextra -Werror ${CMAKE_SUPPRESSED_WARNINGS}")
	endif()

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FALCOSECURITY_LIBS_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FALCOSECURITY_LIBS_COMMON_FLAGS} -std=c++0x")

	set(CMAKE_C_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")

	if(CMAKE_SYSTEM_NAME MATCHES "Linux")
		add_definitions(-DHAS_CAPTURE)
	endif()

	add_definitions(-D__STDC_FORMAT_MACROS)

else() # MSVC
	set(MINIMAL_BUILD ON)

	set(FALCOSECURITY_LIBS_COMMON_FLAGS "-D_CRT_SECURE_NO_WARNINGS -DWIN32 -DMINIMAL_BUILD /EHsc /W3 /Zi")
	set(FALCOSECURITY_LIBS_DEBUG_FLAGS "/MTd /Od")
	set(FALCOSECURITY_LIBS_RELEASE_FLAGS "/MT")

	set(CMAKE_C_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${FALCOSECURITY_LIBS_COMMON_FLAGS}")

	set(CMAKE_C_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")
	set(CMAKE_CXX_FLAGS_DEBUG "${FALCOSECURITY_LIBS_DEBUG_FLAGS}")

	set(CMAKE_C_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${FALCOSECURITY_LIBS_RELEASE_FLAGS}")

	add_definitions(-DHAS_CAPTURE)

endif()
