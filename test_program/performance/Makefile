all:
	cc cap_dns.c -o cap_dns -O2 -L/lib -lcasper /lib/libcap_dns.so.2

	cc dns_origin.c -static -o dns_origin -O2
	cc dns_origin.c  -D MAC -static -o dns_origin_mac -O2




