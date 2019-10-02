# This is to be included from the curl tree,
# to be able to reach curl internals when fuzzing and providing
# IDE support by using cmake.


# If this is enabled, the fuzzers are built as ordinary programs which
# runs test cases through the fuzz targets. This is good for replaying,
# measuring coverage and can be used to evaluate performance.
option(FUZZING_LINK_MAINRUNNER "links the fuzz targets with a main() aimed at replaying old data and/or measuring coverage" On)

# This enables some experimental TLV types to play around with for instance
# proxy fuzzing.
option(FUZZING_ENABLE_EXTENDED_TLVS "enables more tlv types" Off)

if(FUZZING_ENABLE_EXTENDED_TLVS)
if(${CMAKE_VERSION} VERSION_LESS "3.12")
  add_definitions(-DFUZZ_EXTENDED_TLVS=1)
else()
  add_compile_definitions(FUZZ_EXTENDED_TLVS=1)
endif()
endif()

if(ENABLE_FUZZING)

    # Make sure the compiler and compiler flags combination make sense, just
    # for providing a helpful error message.
    if (CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(INFO "fuzzing is enabled and clang is used")
    else()
        if( NOT ${FUZZING_LINK_MAINRUNNER})
            message(FATAL_ERROR "fuzzing is enabled and the clang C compiler is not used - won't work")
        endif()
    endif()

    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(INFO "fuzzing is enabled and clang is used")
    else()
        if( NOT ${FUZZING_LINK_MAINRUNNER})
            message(FATAL_ERROR "fuzzing is enabled and the clang C++ compiler is not used - won't work")
        endif()
    endif()


    # This CMakeFile is included from within the curl repository, point
    # to where the source files for the fuzzers are.
    set(fuzzroot ${CMAKE_SOURCE_DIR}/../curl-fuzzer/intree_fuzzer/)

    # Build the support library for being able to use the existing network
    # fuzzers.
    add_library(fuzzersupport ${fuzzroot}/src/networkfuzzers/TLVMacros.hh
                              ${fuzzroot}/src/networkfuzzers/curl_fuzzer_tlv.cc
                              ${fuzzroot}/src/networkfuzzers/curl_fuzzer_callback.cc
                              ${fuzzroot}/src/networkfuzzers/TLVTraits.hpp
                              ${fuzzroot}/src/networkfuzzers/TLVTraits.cpp)

    # This is for custom mutator support (save some cycles by not building it
    # unless actually fuzzing)
    if( NOT ${FUZZING_LINK_MAINRUNNER})
       add_library(fuzzermutator ${fuzzroot}/src/networkfuzzers/TLVMutator.hpp
                                 ${fuzzroot}/src/networkfuzzers/TLVMutator.cpp)
                             target_link_libraries(fuzzermutator fuzzersupport)
       target_compile_definitions(fuzzermutator PUBLIC -DFUZZER_CUSTOM_MUTATOR=1)
    endif()

    # The mainrunner finds files recursively, and has to use boost filesystem.
    # This should be replaced with the C++17 filesystem support once that
    # can be assumed to exist.
    if(FUZZING_LINK_MAINRUNNER)
        find_package(Boost REQUIRED COMPONENTS filesystem)
        add_library(fuzzermain ${fuzzroot}/src/networkfuzzers/standalone_fuzz_target_runner)
        set_target_properties(fuzzermain PROPERTIES LINKER_LANGUAGE CXX)
        target_link_libraries(fuzzermain Boost::filesystem)
    endif()

    ###########################################################################
    # The curl fuzzers originally written in 2017 are called the network
    # fuzzers, since they use emulated network to operate.
    # They are built in two variants, with and without custom mutation.

    # All network fuzzers are very similar, only differing in what protocols
    # they enable. Hence, use a macro to implement them. Each target will
    # exist in two versions - the default one, and one suffixed _wcm,
    # for using the custom mutator (wcm - with custom mutator).
    macro(implement_fuzzer selector mutatorsuffix)
      string(TOUPPER ${selector} selector_uppercase)
      string(TOLOWER ${selector} selector_lowercase)
      set(name curl_fuzzer_${selector_lowercase}${mutatorsuffix})
      add_executable(${name} ${fuzzroot}/src/networkfuzzers/curl_fuzzer.cc)
      if(FUZZING_LINK_MAINRUNNER)
          target_link_libraries(${name} PRIVATE fuzzermain)
      else()
          target_link_libraries(${name} PRIVATE "-fsanitize=fuzzer")
      endif()
      target_link_libraries(${name} PRIVATE libcurl fuzzersupport)
      if( NOT "${mutatorsuffix}" STREQUAL "")
          # use the custom mutator
          target_link_libraries(${name} PRIVATE fuzzermutator)
          target_compile_definitions(${name} PRIVATE -DFUZZER_CUSTOM_MUTATOR=1)
      endif()
      set(tmp "FUZZ_PROTOCOLS_${selector_uppercase}")
      target_compile_definitions(${name} PRIVATE "-D${tmp}=")
    endmacro ()

    # This is a list of all the network fuzzers
    set(selectors all dict file ftp gopher http https 
                  imap ldap pop3 rtmp rtsp scp sftp smb smtp tftp)

    # For each network fuzzer make one with default mutator and one with
    # custom mutator.
    foreach (X IN ITEMS ${selectors})
        implement_fuzzer(${X} "")     # default mutator
        if( NOT ${FUZZING_LINK_MAINRUNNER})
          implement_fuzzer(${X} "_wcm")  # custom mutator
        endif()
    endforeach ()

    #########################################################################
    # Internal fuzzers
    # These fuzzers do not use network, instead they are more of a traditional
    # fuzzer just invoking functions with fuzz data. They need to reach
    # curl internal API-s and do so by being built resembling how the curl unit
    # tests are built. They will invoke functions guarded by debug only, test
    # only flags set by curl.
    set(internalfuzzers
        fuzz_cookies fuzz_cookies3
        fuzz_netrc
        fuzz_escape fuzz_escape2
        fuzz_doh fuzz_doh2)

    # The fuzzers will be very similar, use a macro to avoid repetition.
    macro(implement_internalfuzzer srcfile)
      set(name internalfuzzer_${srcfile})

      add_executable(${name}
                     ${fuzzroot}/src/insidefuzzers/${srcfile}
                     ${fuzzroot}/src/insidefuzzers/FuzzData.h
                     ${fuzzroot}/src/insidefuzzers/CurlInitializer.h
	                  )

      if(FUZZING_LINK_MAINRUNNER)
          target_link_libraries(${name} PRIVATE fuzzermain)
      else()
          target_link_libraries(${name} PRIVATE "-fsanitize=fuzzer")
      endif()

      target_link_libraries(${name} PRIVATE libcurl)

      # This is needed to get access to curl internals
      target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}/lib")
      # ...and will need curl config which is generated in the build dir
      target_include_directories(${name} PRIVATE  ${CMAKE_BINARY_DIR}/lib)
      # this is a hack. Help welcome.
      target_compile_definitions(${name} PRIVATE BUILDING_LIBCURL)
    endmacro ()
    foreach (X IN ITEMS ${internalfuzzers})
      implement_internalfuzzer(${X})
    endforeach ()
   
    ############################################################################
    # Experimental Boost Asio based fuzzer, for experiments.
    set(name asiohttpfuzz)
    add_executable(${name} ${fuzzroot}/src/asiofuzzer/AsioHttpFuzzer.cpp)
    target_link_libraries(${name} PRIVATE libcurl)
    find_package(Boost REQUIRED COMPONENTS system)
    target_link_libraries(${name} PRIVATE Boost::system)
    if(FUZZING_LINK_MAINRUNNER)
        target_link_libraries(${name} PRIVATE fuzzermain)
    else()
        target_link_libraries(${name} PRIVATE "-fsanitize=fuzzer")
    endif()

endif()
