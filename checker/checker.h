#ifndef CASPER_CHECKER_H
#define CASPER_CHECKER_H

/* DNS checker */
#define BUF_SIZE 1024 // Read in chunks
#define MAXNS	 3  // Limit how many nameservers we parse

int casper_check_dst_ip(const char *label, struct sockaddr *sa);

#endif // CASPER_CHECKER_H
