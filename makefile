all:
	gcc getpacket.c -o getpacket -lpcap
	gcc savepacket.c -o save;acket -lpcap
clean:
	rm getpacket
run:
	sudo ./getpacket
