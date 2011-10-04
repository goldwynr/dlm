all:
	make -C libdlm $@
	make -C dlm_controld $@
	make -C dlm_tool $@

install:
	make -C libdlm $@
	make -C dlm_controld $@
	make -C dlm_tool $@

clean:
	make -C libdlm $@
	make -C dlm_controld $@
	make -C dlm_tool $@

