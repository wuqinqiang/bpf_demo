build:
	 go build -o func func.go && go build -o tracer tracer.go



http:
	sudo ./func


tracer:
	sudo ./tracer --binary func



run1:
	sudo ./tracer --binary ../tracee/tracee --func main.ebpfDemo


clean:
	rm -rf tracer
