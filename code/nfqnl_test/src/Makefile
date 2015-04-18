#LDFLAGS=-lnetfilter_queue # -llibnfnetlink

nfqnl_test:
	$(CC) $(CFLAGS) $(LDFLAGS) -lnfnetlink -lnetfilter_queue nfqnl_test.c -o nfqnl_test 
#nfqnl.o: nfqnl_test.c
#	$(CC) $(CFLAGS)  nfqnl_test.c $(LDFLAGS)


clean:
	rm *.o nfqnl_test
