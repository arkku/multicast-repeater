MODULE = multicast-repeater
BIN = $(MODULE)
SRC = $(wildcard *.go)
DESTDIR ?= /usr/local
BINDIR=$(DESTDIR)/bin
INSTALL=$(BINDIR)/$(BIN)

all: $(BIN)

$(BIN): $(SRC)
	go build -o $@

$(BINDIR)/$(BIN): $(BIN) $(BINDIR)
	install $< "$@"

$(BINDIR):
	install -d $@

install: $(INSTALL)

uninstall:
	-rm -f $(INSTALL)

fmt:
	go fmt

clean:
	go clean

.PHONY: all clean fmt install uninstall
