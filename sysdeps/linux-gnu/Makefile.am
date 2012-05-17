DIST_SUBDIRS = \
	alpha \
	arm \
	ia64 \
	m68k \
	mipsel \
	ppc \
	s390 \
	sparc \
	x86

SUBDIRS = \
	$(HOST_CPU)

noinst_LTLIBRARIES = \
	../libos.la

___libos_la_SOURCES = \
	events.c \
	trace.c \
	proc.c \
	breakpoint.c

___libos_la_LIBADD = \
	libcpu.la

noinst_HEADERS = \
	arch_syscallent.h \
	signalent1.h \
	syscallent1.h \
	trace.h \
	events.h

EXTRA_DIST = \
	arch_mksyscallent \
	mksignalent \
	mksyscallent \
	mksyscallent_s390

MAINTAINERCLEANFILES = \
	Makefile.in
