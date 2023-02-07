#execute_process(COMMAND sh -c "cd ../dep_root && sh ../download_deps.sh")
set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")


set(SRC ${CMAKE_CURRENT_SOURCE_DIR})
set(DEP ${SRC}/dep_root)


if(${CHECKRA1N_VERSION})
    set(CHECKRA1N_VERSION 0.1337.1)
endif()
if( ${LDID})
    set(LDID ldid)
endif()
if( ${LIPO})
    set(LIPO lipo)
endif()

    if(APPLE)
        set(CHECKRA1N_FILE_NAME checkra1n-macos)
    else()
        set(CHECKRA1N_FILE_NAME checkra1n-linux-${CMAKE_SYSTEM_PROCESSOR})
    endif()


execute_process(
        #COMMAND sh -c "curl -LO https://assets.checkra.in/downloads/preview/${CHECKRA1N_VERSION}/${CHECKRA1N_FILE_NAME} && chmod 755 ${CHECKRA1N_FILE_NAME}"
        COMMAND sh -c "curl -LO https://assets.checkra.in/downloads/preview/0.1337.1/${CHECKRA1N_FILE_NAME} && chmod 755 ${CHECKRA1N_FILE_NAME}"
)

if(APPLE)
    execute_process(
            COMMAND sh -c "ldid -Scheckra1n.plist checkra1n"
    )
    execute_process(
            COMMAND lipo -thin ${CMAKE_SYSTEM_PROCESSOR} -output ../src/checkra1n checkra1n-macos
    )
    if(CFLAGS MATCHES "version-min=")
        execute_process(
                COMMAND sh -c "vtool -remove-build-version 1 -replace -output checkra1n ../src/checkra1n && vtool -set-build-version $(FAKE_PLATFORM) $(FAKE_MINOS) $(FAKE_SDK) -replace -output checkra1n checkra1n && install_name_tool -change /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit /System/Library/Frameworks/IOKit.framework/IOKit checkra1n && install_name_tool -change /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation ../src/checkra1n && ${LDID} -Susb.xml ../src/checkra1n"
        )
    endif()
else()
    execute_process(
            COMMAND cp ${CHECKRA1N_FILE_NAME} ../src/checkra1n
    )
endif()

# adds dev mode files
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_executable(palera1n
            main.c
            log.c
            optparse.c
            override_file.c
            pongo_helper.c
            pongo_usb.c
            devhelper.c
            dfuhelper.c
            exec_checkra1n.c
            lock_vars.c
            lockdown_helper.c
            lockdown_helper.h
            checkra1n.c
            checkra1n-kpf-pongo.c
            ramdisk.dmg.c
            binpack.dmg.c
            ../include/palerain.h
            ../include/kerninfo.h
            ../include/ANSI-color-codes.h
            ../include/tui.h
            ../include/xxd-embedded.h
            tui_main.c
            tui_screen_enter_dfu.c
            tui_screen_enter_recovery.c
            tui_screen_jailbreak.c
            tui_screen_main.c
            tui_screen_options.c
            )

elseif(CMAKE_BUILD_TYPE STREQUAL "ASAN")
    add_executable(palera1n
            main.c
            log.c
            optparse.c
            override_file.c
            pongo_helper.c
            pongo_usb.c
            devhelper.c
            dfuhelper.c
            exec_checkra1n.c
            lock_vars.c
            lockdown_helper.c
            lockdown_helper.h
            checkra1n.c
            checkra1n-kpf-pongo.c
            ramdisk.dmg.c
            binpack.dmg.c
            ../include/palerain.h
            ../include/kerninfo.h
            ../include/ANSI-color-codes.h
            ../include/tui.h
            ../include/xxd-embedded.h
            tui_main.c
            tui_screen_enter_dfu.c
            tui_screen_enter_recovery.c
            tui_screen_jailbreak.c
            tui_screen_main.c
            tui_screen_options.c
            )
    add_compile_options(-fsanitize=address,undefined -fsanitize-address-use-after-return=runtime)
else()
    set(CMAKE_BUILD_TYPE "Release")
    add_executable(palera1n
            main.c
            log.c
            optparse.c
            override_file.c
            pongo_helper.c
            pongo_usb.c
            devhelper.c
            dfuhelper.c
            exec_checkra1n.c
            lock_vars.c
            lockdown_helper.c
            lockdown_helper.h
            checkra1n.c
            checkra1n-kpf-pongo.c
            ramdisk.dmg.c
            binpack.dmg.c
            ../include/palerain.h
            ../include/kerninfo.h
            ../include/ANSI-color-codes.h
            ../include/tui.h
            ../include/xxd-embedded.h
            )
endif()


execute_process(
        COMMAND sh -c "curl -Lo ../src/checkra1n-kpf-pongo https://github.com/guacaplushy/checkp4le/raw/main/binaries/checkra1n-kpf-pongo"
)

execute_process(
        COMMAND sh -c "curl -Lo ../src/ramdisk.dmg https://cdn.nickchan.lol/palera1n/c-rewrite/deps/ramdisk.dmg"
)

execute_process(
        COMMAND sh -c "curl -Lo ../src/binpack.dmg https://cdn.nickchan.lol/palera1n/c-rewrite/deps/binpack.dmg"
)

execute_process(
        COMMAND sh -c "cd ../src/ && xxd -iC checkra1n-kpf-pongo > ../src/checkra1n-kpf-pongo.c"
)

execute_process(
        COMMAND sh -c "cd ../src/ && xxd -iC ramdisk.dmg > ../src/ramdisk.dmg.c"
)
execute_process(
        COMMAND sh -c "cd ../src/ && xxd -iC binpack.dmg > ../src/binpack.dmg.c"
)

execute_process(
        COMMAND sh -c "cd ../src/ && xxd -iC checkra1n > ../src/checkra1n.c"
)

include_directories(
        ../include
        ${SRC}
)


target_compile_definitions(palera1n PRIVATE -DPALERAIN_VERSION=\"2.0.0\")

target_include_directories(palera1n PRIVATE
        ${SRC}/include
        ${SRC}
        ${DEP}/include
        )

if(${STATIC})
    target_link_libraries(palera1n
            ${DEP}/lib/libimobiledevice-1.0.a
            ${DEP}/lib/libirecovery-1.0.a
            ${DEP}/lib/usbmuxd-2.0.a
            ${DEP}/lib/libimobiledevice-glue-1.0.a
            ${DEP}/lib/libplist-2.0.a
            ${DEP}/lib/libmbedtls.a
            ${DEP}/lib/libmbedcrypto.a
            ${DEP}/lib/libmbedx509.a
            ${DEP}/lib/libreadline.a
            ${DEP}/lib/libusb-1.0.a
            )
else()
    target_link_libraries(palera1n
            imobiledevice-1.0
            irecovery-1.0
            usbmuxd-2.0
            imobiledevice-glue-1.0
            plist-2.0
            mbedtls
            mbedcrypto
            mbedx509
            readline
            usb-1.0
            )
endif()
if(APPLE)
    add_compile_options(palera1n
            -framework CoreFoundation
            -framework SystemConfiguration
            -framework IOKit
            -framework Security
            )
endif()


if(!BUILD_DATE)
execute_process(COMMAND date OUTPUT_VARIABLE BUILD_DATE)
endif()
if(!BUILD_TAG)
execute_process(COMMAND git describe --dirty --tags --abbrev=7 OUTPUT_VARIABLE BUILD_TAG)
endif()
if(!BUILD_WHOAMI)
    execute_process(COMMAND whoami OUTPUT_VARIABLE BUILD_WHOAMI)
endif ()

set(INCLUDE_DIR /usr/local/include)
include_directories (${INCLUDE_DIR})


add_compile_definitions(
        BUILD_DATE="${BUILD_DATE}"
        BUILD_TAG="${BUILD_TAG}"
        BUILD_WHOAMI="${BUILD_WHOAMI}"
        BUILD_STYLE="${CMAKE_BUILD_TYPE}"
)






# runs during configure






