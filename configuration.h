#ifndef CONFIGURATION_H
#define CONFIGURATION_H

char *opt_api_allow = NULL;
char *opt_api_groups;
char *opt_api_description = PACKAGE_STRING;
int opt_api_port = 4028;
bool opt_api_listen;
bool opt_api_mcast;
char *opt_api_mcast_addr = API_MCAST_ADDR;
char *opt_api_mcast_code = API_MCAST_CODE;
char *opt_api_mcast_des = "";
int opt_api_mcast_port = 4028;
bool opt_api_network;

bool opt_autofan;
bool opt_autoengine;
bool opt_noadl;

bool opt_quiet;
bool opt_realquiet;
#define QUIET	(opt_quiet || opt_realquiet)
bool opt_protocol;

bool opt_compact;
bool opt_incognito;

const int opt_cutofftemp = 95;
int opt_log_interval = 5;
int opt_queue = 1;
int opt_scantime = 7;
int opt_expiry = 28;

static bool opt_submit_stale = true;

bool opt_delaynet;
bool opt_disable_pool;
bool opt_disable_client_reconnect = false;

bool opt_fail_only;
int opt_fail_switch_delay = 60;
static bool opt_fix_protocol;
static bool opt_lowmem;

algorithm_t *opt_algorithm;

static bool opt_removedisabled;

char *opt_socks_proxy = NULL;

char *opt_kernel_path;


#endif /* CONFIGURATION_H */
