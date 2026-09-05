# SPDX-License-Identifier: Apache-2.0
# Build draft-mih-sokolov-scitt-payload-binding from the kramdown-rfc source.
# Toolchain (one-time):
#   gem install kramdown-rfc
#   python3 -m pip install xml2rfc

DRAFT   = draft-mih-sokolov-scitt-payload-binding-03
XML2RFC ?= xml2rfc
KDRFC   ?= kramdown-rfc

.PHONY: all clean idnits refresh-refs rebuild

all: $(DRAFT).xml $(DRAFT).txt

# Force a rebuild from the Markdown source.
#
# `make` decides by modification time, and several routine git operations give a
# generated file a *fresh* mtime without changing its contents -- a fresh clone,
# a checkout, or resolving a conflict with `git checkout --ours`.  When that
# happens make judges the .xml newer than the .md, skips kramdown entirely, and
# regenerates only the .txt from the stale .xml.  The output says "Created file"
# and looks like a successful build while shipping the previous revision's text.
# Use this target after any merge or checkout; never restore a generated file
# from git and then run plain `make`.
rebuild:
	rm -f $(DRAFT).xml $(DRAFT).txt
	$(MAKE) all

$(DRAFT).xml: $(DRAFT).md
	$(KDRFC) $(DRAFT).md > .$(DRAFT).v2.xml
	$(XML2RFC) --v2v3 .$(DRAFT).v2.xml -o $(DRAFT).xml
	@rm -f .$(DRAFT).v2.xml

$(DRAFT).txt: $(DRAFT).xml
	$(XML2RFC) --text --v3 $(DRAFT).xml -o $(DRAFT).txt

idnits: $(DRAFT).txt
	npx --yes @ietf-tools/idnits $(DRAFT).txt

# Re-fetch the bibliographic reference cache.
#
# .refcache/ is COMMITTED so that building the draft never depends on
# bib.ietf.org being reachable.  Every uncached build fetches one file per
# external reference, so an outage at the IETF reds the spec gate on every open
# pull request simultaneously, for reasons unrelated to any of them.
#
# RFC references are immutable and need no refreshing.  References to
# Internet-Drafts are not: run this before submitting a revision so a superseded
# I-D reference cannot be carried forward silently.  See ../RELEASING.md.
refresh-refs:
	rm -rf .refcache
	$(KDRFC) $(DRAFT).md > /dev/null
	@echo "refreshed: $$(ls .refcache | wc -l) references -- review 'git diff' before committing"

clean:
	rm -f .$(DRAFT).v2.xml
