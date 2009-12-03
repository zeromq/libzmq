sitedir=$(CLDIR)/../site/zeromq
zeromqasd=$(CLDIR)/zeromq.asd

install-data-local:
	if test -d $(sitedir); then rm -rdf $(sitedir); fi
	mkdir $(sitedir)
	chown --reference=$(sitedir)/.. $(sitedir)
	cp *.lisp *.asd $(sitedir)
	ln -sf $(sitedir)/zeromq.asd $(zeromqasd)
