SHELL := /bin/sh

ROOT_DIR := $(abspath ..)
GRADLEW := $(ROOT_DIR)/gradlew
ADB ?= adb
APK := $(ROOT_DIR)/example/build/outputs/apk/debug/example-debug.apk
KATHTTP3_DEPS_ROOT ?= $(ROOT_DIR)/third_party/android-deps
DEVICE_SERIAL ?=
TMPDIR ?= $(ROOT_DIR)/.tmp
export TMPDIR

GRADLE_ARGS := --no-daemon -p $(ROOT_DIR) -Pkathttp3DepsRoot=$(abspath $(KATHTTP3_DEPS_ROOT))

.PHONY: help native-deps assemble adbcheck adbinstall clean

help:
	@echo "Targets:"
	@echo "  make assemble    Build the debug APK"
	@echo "  make adbinstall  Build dependencies/APK and install with adb install -r"
	@echo "  make clean       Clean Android build outputs"
	@echo ""
	@echo "Variables:"
	@echo "  KATHTTP3_DEPS_ROOT=/path/to/android/deps (default: ../third_party/android-deps)"
	@echo "  DEVICE_SERIAL=<adb serial>  (required when multiple devices are connected)"
	@echo "  ADB=/path/to/adb"

native-deps:
	@mkdir -p "$(TMPDIR)"
	$(GRADLEW) $(GRADLE_ARGS) buildAndroidNativeDeps

assemble: native-deps
	@mkdir -p "$(TMPDIR)"
	$(GRADLEW) $(GRADLE_ARGS) :example:assembleDebug
	@test -f "$(APK)" || { echo "APK was not produced: $(APK)" >&2; exit 2; }

adbcheck:
	@command -v "$(ADB)" >/dev/null 2>&1 || { echo "adb was not found; set ADB=/path/to/adb" >&2; exit 2; }
	@if [ -n "$(DEVICE_SERIAL)" ]; then \
		"$(ADB)" -s "$(DEVICE_SERIAL)" get-state | grep -qx device || { echo "Device $(DEVICE_SERIAL) is not ready" >&2; exit 2; }; \
	else \
		count=`"$(ADB)" devices | awk 'NR > 1 && $$2 == "device" { count++ } END { print count + 0 }'`; \
		[ "$$count" -eq 1 ] || { echo "Expected exactly one ready device, found $$count. Set DEVICE_SERIAL when multiple devices are connected." >&2; exit 2; }; \
	fi

adbinstall: assemble adbcheck
	@if [ -n "$(DEVICE_SERIAL)" ]; then \
		"$(ADB)" -s "$(DEVICE_SERIAL)" install -r "$(APK)"; \
	else \
		"$(ADB)" install -r "$(APK)"; \
	fi

clean:
	$(GRADLEW) $(GRADLE_ARGS) :example:clean
