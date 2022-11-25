# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang

BPFTOOL_SRC := $(abspath ./3rdparty/bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

LIBBPF_SRC := $(abspath ./3rdparty/libbpf/src)
LIBBPF_OBJ ?= $(abspath $(OUTPUT)/libbpf.a)

HELPERS_SRC := $(abspath ./3rdparty/bcc/libbpf-tools)
UTHASH_SRC := $(abspath ./3rdparty/uthash/src)

APPS = memleak

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/uprobe_helpers.o

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' \
		      "$(1)" \
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

ARCH := $(firstword $(subst -, ,$(shell $(CC) -dumpmachine)))
ARCH := $(shell echo $(ARCH) | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := $(HELPERS_SRC)/$(ARCH)/vmlinux.h

CFLAGS := -g -Wall -Werror
INCLUDES := -I$(OUTPUT) -I$(HELPERS_SRC) -I$(UTHASH_SRC) -I$(dir $(VMLINUX)) -I$(LIBBPF_SRC)/../include/uapi

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1	\
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		\
		INCLUDEDIR= LIBDIR= UAPIDIR=					\
		ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)		\
		install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CFLAGS) -g -O2 -D__TARGET_ARCH_$(ARCH) -target bpf $(INCLUDES) -c $(filter %.c,$^) -o $@

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.o: $(HELPERS_SRC)/%.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(COMMON_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
