# - Find Asciidoctor
# this module looks for asciidoctor
#
# ASCIIDOCTOR_EXECUTABLE - the full path to asciidoc
# ASCIIDOCTOR_FOUND - If false, don't attempt to use asciidoc.
set (PROGRAMFILESX86 "PROGRAMFILES(X86)")

find_program(ASCIIDOCTOR_EXECUTABLE asciidoctor asciidoctor
             PATHS "$ENV{ASCIIDOCTOR_ROOT}"
                   "$ENV{PROGRAMW6432}/asciidoctor"
                   "$ENV{PROGRAMFILES}/asciidoctor"
                   "$ENV{${PROGRAMFILESX86}}/asciidoctor")

find_program(A2X_EXECUTABLE a2x
             PATHS "$ENV{ASCIIDOCTOR_ROOT}"
                   "$ENV{PROGRAMW6432}/asciidoctor"
                   "$ENV{PROGRAMFILES}/asciidoctor"
                   "$ENV{${PROGRAMFILESX86}}/asciidoctor")


include(FindPackageHandleStandardArgs)
find_package_handle_standard_ARGS(AsciiDoctor REQUIRED_VARS ASCIIDOCTOR_EXECUTABLE)
mark_as_advanced(ASCIIDOCTOR_EXECUTABLE)
