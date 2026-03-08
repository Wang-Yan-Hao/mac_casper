#define WITH_CASPER

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/nv.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <casper/cap_dns.h>
#include <errno.h>
#include <fcntl.h>
#include <libcasper.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int
cap_dns_attack(cap_channel_t *chan, const char *cmd)
{
	nvlist_t *nvlin, *nvlout;
	int error, attack_errno = -1;

	/* 1. 建立 Request */
	nvlin = nvlist_create(0);
	if (nvlin == NULL)
		return (ENOMEM);

	nvlist_add_string(nvlin, "cmd", cmd);

	/* 2. 傳送 Request 給 Casper Daemon (nvlin 會被自動 free 掉) */
	nvlout = cap_xfer_nvlist(chan, nvlin);
	if (nvlout == NULL) {
		printf("cap_xfer_nvlist failed\n");
		return (EAI_MEMORY);
	}

	printf("Request sent successfully: %s\n", cmd);

	/* 3. 讀取 Casper 原生的 error 狀態 */
	error = (int)nvlist_get_number(nvlout, "error");
	if (error != 0) {
		printf("Casper service returned internal error: %d\n", error);
	}

	/* 4. 讀取我們自定義的 attack_errno */
	if (nvlist_exists_number(nvlout, "attack_errno")) {
		attack_errno = (int)nvlist_get_number(nvlout, "attack_errno");
		printf("Attack result (attack_errno): %d\n", attack_errno);
	} else {
		printf(
		    "Warning: 'attack_errno' not found. Check if Daemon handles this cmd.\n");
	}

	nvlist_destroy(nvlout);

	/* 回傳攻擊測試的結果，而不是 Casper 的 error */
	return (attack_errno);
}

int
main(void)
{
	cap_channel_t *cap_casper;
	cap_channel_t *cap_net;
	int attack_err;

	cap_casper = cap_init();
	if (cap_casper == NULL) {
		perror("cap_init");
		return (1);
	}

	cap_net = cap_service_open(cap_casper, "system.dns");
	if (cap_net == NULL) {
		perror("cap_service_open(system.dns)");
		cap_close(cap_casper);
		return (1);
	}

	/* * Simulate attack
	 * 注意：這裡必須與 Daemon 端的 strcmp 完全一致（全大寫）
	 */
	attack_err = cap_dns_attack(cap_net, "ATTACK_EXEC");

	/* 判斷 MAC Policy 是否成功攔截 */
	if (attack_err == EACCES || attack_err == EPERM) {
		printf("SUCCESS: MAC Policy blocked the attack! (errno = %d)\n",
		    attack_err);
	} else if (attack_err == 0) {
		printf("FAILED: Attack bypassed the policy! (errno = 0)\n");
	} else {
		printf(
		    "UNKNOWN: Attack failed for another reason (errno = %d)\n",
		    attack_err);
	}

	printf("main end\n");

	cap_close(cap_net);
	cap_close(cap_casper);
	return (0);
}
