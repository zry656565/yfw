make:
	gcc src/filter.c -o filter -lpcap
	gcc src/tcpLimit.c -o tcpLimit -lpcap

clean:
	rm filter tcpLimit