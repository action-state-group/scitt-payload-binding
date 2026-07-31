# SPDX-License-Identifier: Apache-2.0
# Build draft-mih-sokolov-scitt-payload-binding from the kramdown-rfc source.
# Toolchain (one-time):
#   gem install kramdown-rfc
#   python3 -m pip install xml2rfc

DRAFT   = draft-mih-sokolov-scitt-payload-binding-00
XML2RFC ?= xml2rfc
KDRFC   ?= kramdown-rfc

.PHONY: all clean idnits

all: $(DRAFT).xml $(DRAFT).txt

$(DRAFT).xml: $(DRAFT).md
	$(KDRFC) $(DRAFT).md > .$(DRAFT).v2.xml
	$(XML2RFC) --v2v3 .$(DRAFT).v2.xml -o $(DRAFT).xml
	@rm -f .$(DRAFT).v2.xml

$(DRAFT).txt: $(DRAFT).xml
	$(XML2RFC) --text --v3 $(DRAFT).xml -o $(DRAFT).txt

idnits: $(DRAFT).txt
	npx --yes @ietf-tools/idnits $(DRAFT).txt

clean:
	rm -f .$(DRAFT).v2.xml
