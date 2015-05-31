make:
	gcc src/filterARP.c -o filterARP -lpcap

clean:
	rm filterARP