#LDFLAGS=-lnetfilter_queue # -llibnfnetlink

nfqnl_xor:
	$(CC) $(CFLAGS) $(LDFLAGS) -lnfnetlink -lnetfilter_queue nfqnl_xor.c -o nfqnl_xor
#nfqnl.o: nfqnl_test.c
#	$(CC) $(CFLAGS)  nfqnl_test.c $(LDFLAGS)


clean:
	rm *.o nfqnl_xor
