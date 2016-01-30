# - Find Asciidoc
# this module looks for asciidoc and a2x
#
# ASCIIDOC_EXECUTABLE - the full path to asciidoc
# ASCIIDOC_FOUND - If false, don't attempt to use asciidoc.
# A2X_EXECUTABLE - the full path to a2x
# A2X_FOUND - If false, don't attempt to use a2x.

set (PROGRAMFILESX86 "PROGRAMFILES(X86)")

find_program(ASCIIDOC_EXECUTABLE asciidoc asciidoc.py
             PATHS "$ENV{ASCIIDOC_ROOT}"
                   "$ENV{PROGRAMW6432}/asciidoc"
                   "$ENV{PROGRAMFILES}/asciidoc"
                   "$ENV{${PROGRAMFILESX86}}/asciidoc")

find_program(A2X_EXECUTABLE a2x
             PATHS "$ENV{ASCIIDOC_ROOT}"
                   "$ENV{PROGRAMW6432}/asciidoc"
                   "$ENV{PROGRAMFILES}/asciidoc"
                   "$ENV{${PROGRAMFILESX86}}/asciidoc")


include(FindPackageHandleStandardArgs)
find_package_handle_standard_ARGS(AsciiDoc REQUIRED_VARS ASCIIDOC_EXECUTABLE)
mark_as_advanced(ASCIIDOC_EXECUTABLE A2X_EXECUTABLE)
