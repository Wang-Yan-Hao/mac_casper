all:
	cc cap_dns.c -o cap_dns -O0 -L/lib -lcasper /lib/libcap_dns.so.2
	cc dns_origin.c -static -o dns_origin -O0
	cc dns_origin.c -D MAC -static -o dns_origin_mac -O0
	cc dns_qps.c -o dns_qps -O0  -lcasper /lib/libcap_dns.so.2

