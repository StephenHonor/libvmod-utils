AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_utils.la

libvmod_utils_la_SOURCES = \
	vmod_utils.c

nodist_libvmod_utils_la_SOURCES = \
	vcc_utils_if.c \
	vcc_utils_if.h

dist_man_MANS = vmod_utils.3

@BUILD_VMOD_UTILS@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_utils="$(VMOD_UTILS)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_utils.vcc \
	$(VMOD_TESTS)
