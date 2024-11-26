# This is an oversimplified Makefile to get you started

XDG_CONFIG_HOME := $(if $(XDG_CONFIG_HOME),$(XDG_CONFIG_HOME),$(HOME)/.config)
BINDIR ?= ${HOME}/.local/bin

all: clean build install

build:
	go build -o messh messh.go

install: build
	mkdir -p "${XDG_CONFIG_HOME}/messh" "${BINDIR}"
	cp messh "${BINDIR}/messh"
	cp messh.sample.conf "${XDG_CONFIG_HOME}/messh/messh.sample.conf"

uninstall:
	rm -f "${XDG_CONFIG_HOME}/messh/messh.sample.conf" "${BINDIR}/messh"

clean:
	rm -f messh
