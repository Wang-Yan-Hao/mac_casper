CC = cc
CFLAGS = -g
LDFLAGS = -L/lib
LDLIBS = -lcasper /lib/libcap_dns.so.2  # Explicitly link libcap_dns
TARGET = base
SRC = base.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
