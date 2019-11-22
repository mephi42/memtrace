include $(top_srcdir)/Makefile.tool.am

EXTRA_DIST = docs/mt-manual.xml

#----------------------------------------------------------------------------
# memtrace-<platform>
#----------------------------------------------------------------------------

noinst_PROGRAMS  = memtrace-@VGCONF_ARCH_PRI@-@VGCONF_OS@
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += memtrace-@VGCONF_ARCH_SEC@-@VGCONF_OS@
endif

MEMTRACE_SOURCES_COMMON = mt_main.c

memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_SOURCES      = \
	$(MEMTRACE_SOURCES_COMMON)
memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) \
	-I$(top_srcdir)/coregrind
memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS       = $(LTO_CFLAGS) \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_PRI_CAPS@)
memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_PRI_CAPS@)
memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_PRI@ \
	$(LINK) \
	$(memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS) \
	$(memtrace_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS)

if VGCONF_HAVE_PLATFORM_SEC
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_SOURCES      = \
	$(MEMTRACE_SOURCES_COMMON)
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) \
	-I$(top_srcdir)/coregrind
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS       = $(LTO_CFLAGS) \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_SEC_CAPS@)
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_SEC_CAPS@)
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_SEC@ \
	$(LINK) \
	$(memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS) \
	$(memtrace_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS)
endif


