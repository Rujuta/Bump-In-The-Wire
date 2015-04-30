#LDFLAGS=-lnetfilter_queue # -llibnfnetlink

nfqnl_drop:
	$(CC) $(CFLAGS) $(LDFLAGS) -lnfnetlink -lnetfilter_queue nfqnl_drop.c -o nfqnl_drop
#nfqnl.o: nfqnl_drop.c
#	$(CC) $(CFLAGS)  nfqnl_drop.c $(LDFLAGS)


clean:
	rm *.o nfqnl_drop
