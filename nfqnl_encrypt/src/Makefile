#LDFLAGS=-lnetfilter_queue # -llibnfnetlink

nfqnl_encrypt:
	$(CC) $(CFLAGS) $(LDFLAGS) -lnfnetlink -lnetfilter_queue -lcrypto -lssl nfqnl_ssl.c -o nfqnl_encrypt
#nfqnl.o: nfqnl_test.c
#	$(CC) $(CFLAGS)  nfqnl_test.c $(LDFLAGS)


clean:
	rm *.o nfqnl_encrypt
