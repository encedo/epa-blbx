all: blbx 


blbx: blbx.c 
	$(CC) $(CFLAGS) -Wall -o blbx blbx.c cJSON.c $(LIBS)

