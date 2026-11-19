SLANGC ?= slangc

.PHONY: test
test:
	$(SLANGC) test src/sns
