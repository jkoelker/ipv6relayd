# This Makefile lets you run the devkit image and all related commands in the
# exact same way they are executed in CI. The only requirement is that you have
# Podman or Docker installed and running on your machine.

SHELL := /bin/bash
INTERACTIVE := $(shell [ -t 0 ] && echo 1)

root_mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
REPO_ROOT := $(realpath $(dir $(root_mkfile_path)))

CONTAINER_TOOL ?= podman
ifeq ($(shell command -v $(CONTAINER_TOOL)),)
	CONTAINER_TOOL := docker
endif

# Rootless Podman service socket (override if your socket lives elsewhere).
PODMAN_SOCK ?= $(XDG_RUNTIME_DIR)/podman/podman.sock
CONTAINER_URL :=
ifeq ($(CONTAINER_TOOL),podman)
	ifneq ($(wildcard $(PODMAN_SOCK)),)
		CONTAINER_URL := --url unix://$(PODMAN_SOCK)
	endif
endif

# Preserve the executable name for tool-specific branches.
CONTAINER_TOOL_NAME := $(CONTAINER_TOOL)

# Single helper for container CLI invocations. Usage:
#   $(call container,<subcmd>,<args...>)
container = $(CONTAINER_TOOL) $(CONTAINER_URL) $(1) $(2)

# Common mounts/working-dir used by most run invocations.
WORKSPACE_MOUNT := -v $(REPO_ROOT):/workspace -w /workspace

DEVKIT_IMAGE ?= ipv6relayd-devkit:local
DEVKIT_STAMP ?= $(REPO_ROOT)/.devkit-$(subst :,.,$(subst /,-,$(DEVKIT_IMAGE)))

# Keep stamp in sync: if the image is gone locally, drop the stamp so Make rebuilds.
ifneq ($(shell command -v $(CONTAINER_TOOL_NAME)),)
ifeq ($(shell $(CONTAINER_TOOL_NAME) image ls --quiet "$(DEVKIT_IMAGE)"),)
  junk := $(shell rm -f "$(DEVKIT_STAMP)")
endif
endif

# Defaults for non-podman engines; override when using podman.
DEVKIT_CGROUP_FLAG := --cgroupns=host
CGROUP_MOUNT       := -v /sys/fs/cgroup:/sys/fs/cgroup:rw
ifeq ($(CONTAINER_TOOL),podman)
	DEVKIT_CGROUP_FLAG := --systemd=always
	CGROUP_MOUNT       :=
endif

DEVKIT_EXTRA_ARGS :=
ifeq ($(INTERACTIVE),1)
	DEVKIT_EXTRA_ARGS += --tty --interactive
endif

DEVKIT_ARGS := --rm $(WORKSPACE_MOUNT) $(DEVKIT_EXTRA_ARGS)

.PHONY: devkit-image
devkit-image: $(DEVKIT_STAMP)

$(DEVKIT_STAMP): Containerfile.devkit go.mod go.sum
	@if $(call container,image,inspect $(DEVKIT_IMAGE) >/dev/null 2>&1); then \
		echo "Devkit image $(DEVKIT_IMAGE) already present; skipping build."; \
	else \
		echo "Building devkit image $(DEVKIT_IMAGE)"; \
		$(call container,build,-f Containerfile.devkit -t $(DEVKIT_IMAGE) $(REPO_ROOT)); \
	fi
	@touch $@

.PHONY: shell
shell: devkit-image
	$(call container,run,$(DEVKIT_ARGS) $(DEVKIT_IMAGE) /bin/bash)

.PHONY: lint
lint: devkit-image
	$(call container,run,$(DEVKIT_ARGS) $(DEVKIT_IMAGE) golangci-lint run -v --fix ./...)

.PHONY: test
test: devkit-image
	@pkgs=$$($(call container,run,--rm $(WORKSPACE_MOUNT) $(DEVKIT_IMAGE) go list ./... | grep -v "/integration")); \
	$(call container,run,$(DEVKIT_ARGS) $(DEVKIT_IMAGE) go test -v $$pkgs)

.PHONY: clean-devkit
clean-devkit:
	rm -f $(DEVKIT_STAMP)
	$(call container,image,rm -f $(DEVKIT_IMAGE) >/dev/null 2>&1 || true)

.PHONY: clean
clean: clean-devkit

.PHONY: integration
integration: devkit-image
	@cid=$$($(call container,run,-d --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW --device /dev/net/tun $(DEVKIT_CGROUP_FLAG) --tmpfs /run --tmpfs /tmp $(if $(CGROUP_MOUNT),$(CGROUP_MOUNT)) $(WORKSPACE_MOUNT) -- $(DEVKIT_IMAGE) /lib/systemd/systemd)); \
	status=0; \
	$(call container,exec,$$cid sh -c '\
		tmpbin=$$(mktemp /integration.test.XXXXXX); \
		trap "rm -f $$tmpbin" EXIT; \
		go test -count=1 -c -o $$tmpbin ./integration && \
		chmod +x $$tmpbin && \
		(cd /workspace/integration && $$tmpbin -test.v -test.count=1)') || status=$$?; \
	if [ $$status -ne 0 ]; then $(call container,logs,$$cid) || true; fi; \
	$(call container,stop,-t 0 $$cid >/dev/null 2>&1 || true); \
	$(call container,rm,-f $$cid >/dev/null 2>&1 || true); \
	exit $$status
