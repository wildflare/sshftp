CC     = gcc
TARGET = sshftp.exe
CFLAGS = -Wall -O2
LIBS   = -Wl,-Bstatic -lssh2 -lssl -lcrypto -lz \
         -Wl,-Bdynamic -lws2_32 -lgdi32 -lcrypt32 -lbcrypt \
         -static-libgcc

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)