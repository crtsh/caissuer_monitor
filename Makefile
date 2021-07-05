all: clean caissuer_monitor

# Tidy up files created by compiler/linker.
clean:
	rm -f bin/caissuer_monitor

caissuer_monitor:
	go build -ldflags "-X main.build_date=`date -u +%Y-%m-%d.%H:%M:%S` -X main.svn_revision=`svnversion -n`" caissuer_monitor.go processor_main.go
