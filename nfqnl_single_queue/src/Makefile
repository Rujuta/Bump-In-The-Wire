#LDFLAGS=-lnetfilter_queue # -llibnfnetlink

nfqnl_single_queue:
	$(CC) $(CFLAGS) $(LDFLAGS) -lnfnetlink -lnetfilter_queue -lcrypto -lssl nfqnl_ssl.c -o nfqnl_single_queue
#nfqnl.o: nfqnl_test.c
#	$(CC) $(CFLAGS)  nfqnl_test.c $(LDFLAGS)


clean:
	rm *.o nfqnl_single_queue
