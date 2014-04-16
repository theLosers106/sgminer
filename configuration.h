#ifndef CONFIGURATION_H
#define CONFIGURATION_H

/* autoconf-generated definitions. */
#include "config.h"

/* Configuration file buffer. */
char *cnfbuf = NULL;

static int fileconf_load;

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

char *load_config(const char *arg, void __maybe_unused *unused);
char *parse_config(json_t *config, bool fileconf, int parent_iteration);

char *set_default_config(const char *arg);

void default_save_file(char *filename);

void load_default_config(void);

char *set_algo(const char *arg);
char *set_nfactor(const char *arg);

char *set_api_allow(const char *arg);
char *set_api_groups(const char *arg);
char *set_api_description(const char *arg);
char *set_api_mcast_addr(const char *arg);
char *set_api_mcast_addr(const char *arg);
char *set_api_mcast_code(const char *arg);
char *set_api_mcast_des(const char *arg);

char *set_null(const char __maybe_unused *arg);

char *set_temp_cutoff(char *arg);

char* set_sharelog(char *arg);

char *set_schedtime(const char *arg, struct schedtime *st);
char *set_balance(enum pool_strategy *strategy);
char *set_loadbalance(enum pool_strategy *strategy);
char *set_rotate(const char *arg, int *i);
char *set_rr(enum pool_strategy *strategy);

char *set_int_range(const char *arg, int *i, int min, int max);
void get_intrange(char *arg, int *val1, int *val2);
char *set_int_0_to_9999(const char *arg, int *i);
char *set_int_1_to_65535(const char *arg, int *i);
char *set_int_0_to_10(const char *arg, int *i);
char *set_int_1_to_10(const char *arg, int *i);

char *set_devices(char *arg);

/* Used in configuration parsing (get pool being set up). */
struct pool* get_current_pool();

char *set_pool_priority(char *arg);
char *set_pool_description(char *arg);
char *set_pool_state(char *arg);
char *set_pool_name(char *arg);
char *set_poolname_deprecated(char *arg);
char *set_pool_algorithm(const char *arg);
char *set_pool_nfactor(const char *arg);
char *set_url(char *arg);
char *set_user(const char *arg);
char *set_pass(const char *arg);
char *set_userpass(const char *arg);
char *set_quota(char *arg);

char *enable_debug(bool *flag);

#endif /* CONFIGURATION_H */
