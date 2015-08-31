VERSION := 1.0.1
LAST_TAG := $(shell git describe --abbrev=0 --tags)

USER := rphillips
EXECUTABLE := gosec

GO15VENDOREXPERIMENT = 1

# only include the amd64 binaries, otherwise the github release will become
# too big
UNIX_EXECUTABLES := \
	darwin/amd64/$(EXECUTABLE) \
	freebsd/amd64/$(EXECUTABLE) \
	linux/amd64/$(EXECUTABLE)

COMPRESSED_EXECUTABLES=$(UNIX_EXECUTABLES:%=%.tar.bz2)
COMPRESSED_EXECUTABLE_TARGETS=$(COMPRESSED_EXECUTABLES:%=bin/%)

UPLOAD_CMD = github-release upload -u $(USER) -r $(EXECUTABLE) -t $(LAST_TAG) -n $(subst /,-,$(FILE)) -f bin/$(FILE)
BUILD_FLAGS = -ldflags "-X main.version=$(shell git describe --tags)"

all: $(EXECUTABLE)

# arm
bin/linux/arm/5/$(EXECUTABLE):
	GOARM=5 GOARCH=arm GOOS=linux go build $(BUILD_FLAGS) -o "$@"
bin/linux/arm/7/$(EXECUTABLE):
	GOARM=7 GOARCH=arm GOOS=linux go build $(BUILD_FLAGS) -o "$@"

# 386
bin/darwin/386/$(EXECUTABLE):
	GOARCH=386 GOOS=darwin go build $(BUILD_FLAGS) -o "$@"
bin/linux/386/$(EXECUTABLE):
	GOARCH=386 GOOS=linux go build $(BUILD_FLAGS) -o "$@"
bin/windows/386/$(EXECUTABLE):
	GOARCH=386 GOOS=windows go build $(BUILD_FLAGS) -o "$@"

# amd64
bin/freebsd/amd64/$(EXECUTABLE):
	GOARCH=amd64 GOOS=freebsd go build $(BUILD_FLAGS) -o "$@"
bin/darwin/amd64/$(EXECUTABLE):
	GOARCH=amd64 GOOS=darwin go build $(BUILD_FLAGS) -o "$@"
bin/linux/amd64/$(EXECUTABLE):
	GOARCH=amd64 GOOS=linux go build $(BUILD_FLAGS) -o "$@"
bin/windows/amd64/$(EXECUTABLE).exe:
	GOARCH=amd64 GOOS=windows go build $(BUILD_FLAGS) -o "$@"

# compressed artifacts, makes a huge difference (Go executable is ~9MB,
# after compressing ~2MB)
%.tar.bz2: %
	tar -jcvf "$<.tar.bz2" "$<"
%.zip: %.exe
	zip "$@" "$<"

# git tag -a v$(RELEASE) -m 'release $(RELEASE)'
release: $(COMPRESSED_EXECUTABLE_TARGETS)
	git push && git push --tags
	github-release release -u $(USER) -r $(EXECUTABLE) \
		-t $(LAST_TAG) -n $(LAST_TAG) || true
	$(foreach FILE,$(COMPRESSED_EXECUTABLES),$(UPLOAD_CMD);)

$(EXECUTABLE):
	go build $(BUILD_FLAGS) -o "$@"

install:
	go install $(BUILD_FLAGS)

clean:
	rm go-app || true
	rm $(EXECUTABLE) || true
	rm -rf bin/

.PHONY: clean release dep install
