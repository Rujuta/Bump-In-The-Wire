#LDFLAGS=-lnetfilter_queue # -llibnfnetlink

nfqnl_xor_two_queues:
	$(CC) $(CFLAGS) $(LDFLAGS) -lnfnetlink -lnetfilter_queue -lcrypto -lssl nfqnl_xor_two_queues.c -o nfqnl_xor_two_queues
#nfqnl.o: nfqnl_test.c
#	$(CC) $(CFLAGS)  nfqnl_test.c $(LDFLAGS)


clean:
	rm *.o nfqnl_xor_two_queues
