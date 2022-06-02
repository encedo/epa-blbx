all: blbx 


blbx: blbx.c 
	$(CC) $(CFLAGS) -o blbx blbx.c cJSON.c -lm

