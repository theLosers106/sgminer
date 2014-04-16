/*
 * Copyright 2014 sgminer developers (see AUTHORS.md)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at
 * your option) any later version.  See COPYING for more details.
 */

/* TODO: four-space whitespace */

#include "configuration.h"

/* Used in config parsing, e.g. pool array. */
static int json_array_index = -1;

static int total_urls;

static const char def_conf[] = "sgminer.conf";
static char *default_config;
static int include_count;

static struct pool *add_url(void)
{
	total_urls++;
	if (total_urls > total_pools)
		add_pool();
	return pools[total_urls - 1];
}

static void setup_url(struct pool *pool, char *arg)
{
	arg = get_proxy(arg, pool);

	if (detect_stratum(pool, arg))
		return;

	opt_set_charp(arg, &pool->rpc_url);
	if (strncmp(arg, "http://", 7) &&
	    strncmp(arg, "https://", 8)) {
		char *httpinput;

		httpinput = (char *)malloc(255);
		if (!httpinput)
			quit(1, "Failed to malloc httpinput");
		strcpy(httpinput, "http://");
		strncat(httpinput, arg, 248);
		pool->rpc_url = httpinput;
	}
}

char *load_config(const char *arg, void __maybe_unused *unused)
{
	json_error_t err;
	json_t *config;
	char *json_error;
	size_t siz;

	if (!cnfbuf)
		cnfbuf = strdup(arg);

	if (++include_count > JSON_MAX_DEPTH)
		return JSON_MAX_DEPTH_ERR;

#if JANSSON_MAJOR_VERSION > 1
	config = json_load_file(arg, 0, &err);
#else
	config = json_load_file(arg, &err);
#endif
	if (!json_is_object(config)) {
		siz = JSON_LOAD_ERROR_LEN + strlen(arg) + strlen(err.text);
		json_error = (char *)malloc(siz);
		if (!json_error)
			quit(1, "Malloc failure in json error");

		snprintf(json_error, siz, JSON_LOAD_ERROR, arg, err.text);
		return json_error;
	}

	config_loaded = true;

	/* Parse the config now, so we can override it.  That can keep pointers
	 * so don't free config object. */
	return parse_config(config, true, -1);
}

char *parse_config(json_t *config, bool fileconf, int parent_iteration)
{
	static char err_buf[200];
	struct opt_table *opt;
	json_t *val;

	json_array_index = parent_iteration;

	if (fileconf && !fileconf_load)
		fileconf_load = 1;

	for (opt = opt_config_table; opt->type != OPT_END; opt++) {
		char *p, *name;

		/* We don't handle subtables. */
		assert(!(opt->type & OPT_SUBTABLE));

		if (!opt->names)
			continue;

		/* Pull apart the option name(s). */
		name = strdup(opt->names);
		for (p = strtok(name, "|"); p; p = strtok(NULL, "|")) {
			char *err = NULL;

			/* Ignore short options. */
			if (p[1] != '-')
				continue;

			val = json_object_get(config, p+2);
			if (!val)
				continue;

			if ((opt->type & OPT_HASARG) && json_is_string(val)) {
				err = opt->cb_arg(json_string_value(val),
						  opt->u.arg);
			} else if ((opt->type & OPT_HASARG) && json_is_array(val)) {
				size_t n, size = json_array_size(val);

				for (n = 0; n < size && !err; n++) {
					if (json_is_string(json_array_get(val, n)))
						err = opt->cb_arg(json_string_value(json_array_get(val, n)), opt->u.arg);
					else if (json_is_object(json_array_get(val, n)))
					{
						err = parse_config(json_array_get(val, n), false, n);
					}
				}
			} else if ((opt->type & OPT_NOARG) && json_is_true(val))
				err = opt->cb(opt->u.arg);
			else
				err = "Invalid value";

			if (err) {
				/* Allow invalid values to be in configuration
				 * file, just skipping over them provided the
				 * JSON is still valid after that. */
				if (fileconf) {
					applog(LOG_WARNING, "Skipping config option %s: %s", p, err);
					fileconf_load = -1;
				} else {
					snprintf(err_buf, sizeof(err_buf), "Error parsing JSON option %s: %s",
						p, err);
					return err_buf;
				}
			}
		}
		free(name);
	}

	val = json_object_get(config, JSON_INCLUDE_CONF);
	if (val && json_is_string(val))
		return load_config(json_string_value(val), NULL);

	return NULL;
}

/* add a mutex if this needs to be thread safe in the future */
static struct JE {
	char *buf;
	struct JE *next;
} *jedata = NULL;

static void json_escape_free()
{
	struct JE *jeptr = jedata;
	struct JE *jenext;

	jedata = NULL;

	while (jeptr) {
		jenext = jeptr->next;
		free(jeptr->buf);
		free(jeptr);
		jeptr = jenext;
	}
}

static char *json_escape(char *str)
{
	struct JE *jeptr;
	char *buf, *ptr;

	/* 2x is the max, may as well just allocate that */
	ptr = buf = (char *)malloc(strlen(str) * 2 + 1);

	jeptr = (struct JE *)malloc(sizeof(*jeptr));

	jeptr->buf = buf;
	jeptr->next = jedata;
	jedata = jeptr;

	while (*str) {
		if (*str == '\\' || *str == '"')
			*(ptr++) = '\\';

		*(ptr++) = *(str++);
	}

	*ptr = '\0';

	return buf;
}

void write_config(FILE *fcfg)
{
	int i;

	/* Write pool values */
	fputs("{\n\"pools\" : [", fcfg);
	for(i = 0; i < total_pools; i++) {
		struct pool *pool = pools[i];

		/* Using get_pool_name() here is unsafe if opt_incognito is true. */
		if (strcmp(pool->name, "") != 0) {
			fprintf(fcfg, "\n\t\t\"name\" : \"%s\",", json_escape(pool->name));
		}
		if (strcmp(pool->description, "") != 0) {
			fprintf(fcfg, "\n\t\t\"description\" : \"%s\",", json_escape(pool->description));
		}
		if (pool->quota != 1) {
			fprintf(fcfg, "%s\n\t{\n\t\t\"quota\" : \"%s%s%s%d;%s\",", i > 0 ? "," : "",
				pool->rpc_proxy ? json_escape((char *)proxytype(pool->rpc_proxytype)) : "",
				pool->rpc_proxy ? json_escape(pool->rpc_proxy) : "",
				pool->rpc_proxy ? "|" : "",
				pool->quota,
				json_escape(pool->rpc_url));
		} else {
			fprintf(fcfg, "%s\n\t{\n\t\t\"url\" : \"%s%s%s%s\",", i > 0 ? "," : "",
				pool->rpc_proxy ? json_escape((char *)proxytype(pool->rpc_proxytype)) : "",
				pool->rpc_proxy ? json_escape(pool->rpc_proxy) : "",
				pool->rpc_proxy ? "|" : "",
				json_escape(pool->rpc_url));
		}
		fprintf(fcfg, "\n\t\t\"user\" : \"%s\",", json_escape(pool->rpc_user));
		fprintf(fcfg, "\n\t\t\"pass\" : \"%s\"\n\t}", json_escape(pool->rpc_pass));
		}
	fputs("\n]\n", fcfg);

	/* Write only if there are usable GPUs */
	if (nDevs) {
		fputs(",\n\"intensity\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, gpus[i].dynamic ? "%sd" : "%s%d", i > 0 ? "," : "", gpus[i].intensity);

		fputs("\",\n\"xintensity\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].xintensity);

		fputs("\",\n\"rawintensity\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].rawintensity);

		/* All current kernels only support vector=1 */
		/* fputs("\",\n\"vectors\" : \"", fcfg); */
		/* for(i = 0; i < nDevs; i++) */
		/* 	fprintf(fcfg, "%s%d", i > 0 ? "," : "", */
		/* 		gpus[i].vwidth); */

		fputs("\",\n\"worksize\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "",
				(int)gpus[i].work_size);

		fputs("\",\n\"kernel\" : \"", fcfg);
		for(i = 0; i < nDevs; i++) {
			fprintf(fcfg, "%s", i > 0 ? "," : "");
			fprintf(fcfg, "%s", gpus[i].kernelname);
		}

		fputs("\",\n\"lookup-gap\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "",
				(int)gpus[i].opt_lg);

		fputs("\",\n\"thread-concurrency\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "",
				(int)gpus[i].opt_tc);

		fputs("\",\n\"shaders\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "",
				(int)gpus[i].shaders);

		fputs("\",\n\"gpu-threads\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "",
				(int)gpus[i].threads);

#ifdef HAVE_ADL
		fputs("\",\n\"gpu-engine\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d-%d", i > 0 ? "," : "", gpus[i].min_engine, gpus[i].gpu_engine);

		fputs("\",\n\"gpu-fan\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d-%d", i > 0 ? "," : "", gpus[i].min_fan, gpus[i].gpu_fan);

		fputs("\",\n\"gpu-memclock\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].gpu_memclock);

		fputs("\",\n\"gpu-memdiff\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].gpu_memdiff);

		fputs("\",\n\"gpu-powertune\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].gpu_powertune);

		fputs("\",\n\"gpu-vddc\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%1.3f", i > 0 ? "," : "", gpus[i].gpu_vddc);

		fputs("\",\n\"temp-cutoff\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].cutofftemp);

		fputs("\",\n\"temp-overheat\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].adl.overtemp);

		fputs("\",\n\"temp-target\" : \"", fcfg);
		for(i = 0; i < nDevs; i++)
			fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].adl.targettemp);
#endif

		fputs("\"", fcfg);
	}
#ifdef HAVE_ADL
	if (opt_reorder)
		fprintf(fcfg, ",\n\"gpu-reorder\" : true");
#endif

	/* Simple bool and int options */
	struct opt_table *opt;
	for (opt = opt_config_table; opt->type != OPT_END; opt++) {
		char *p, *name = strdup(opt->names);
		for (p = strtok(name, "|"); p; p = strtok(NULL, "|")) {
			if (p[1] != '-')
				continue;
			if (opt->type & OPT_NOARG &&
			   ((void *)opt->cb == (void *)opt_set_bool || (void *)opt->cb == (void *)opt_set_invbool) &&
			   (*(bool *)opt->u.arg == ((void *)opt->cb == (void *)opt_set_bool)))
				fprintf(fcfg, ",\n\"%s\" : true", p+2);

			if (opt->type & OPT_HASARG &&
			   ((void *)opt->cb_arg == (void *)set_int_0_to_9999 ||
			   (void *)opt->cb_arg == (void *)set_int_1_to_65535 ||
			   (void *)opt->cb_arg == (void *)set_int_0_to_10 ||
			   (void *)opt->cb_arg == (void *)set_int_1_to_10) && opt->desc != opt_hidden)
				fprintf(fcfg, ",\n\"%s\" : \"%d\"", p+2, *(int *)opt->u.arg);
		}
	}

	/* Special case options */
	fprintf(fcfg, ",\n\"shares\" : \"%d\"", opt_shares);
	if (pool_strategy == POOL_BALANCE)
		fputs(",\n\"balance\" : true", fcfg);
	if (pool_strategy == POOL_LOADBALANCE)
		fputs(",\n\"load-balance\" : true", fcfg);
	if (pool_strategy == POOL_ROUNDROBIN)
		fputs(",\n\"round-robin\" : true", fcfg);
	if (pool_strategy == POOL_ROTATE)
		fprintf(fcfg, ",\n\"rotate\" : \"%d\"", opt_rotate_period);
#if defined(unix) || defined(__APPLE__)
	if (opt_stderr_cmd && *opt_stderr_cmd)
		fprintf(fcfg, ",\n\"monitor\" : \"%s\"", json_escape(opt_stderr_cmd));
#endif // defined(unix)
	if (opt_kernel_path && *opt_kernel_path) {
		char *kpath = strdup(opt_kernel_path);
		if (kpath[strlen(kpath)-1] == '/')
			kpath[strlen(kpath)-1] = 0;
		fprintf(fcfg, ",\n\"kernel-path\" : \"%s\"", json_escape(kpath));
	}
	if (schedstart.enable)
		fprintf(fcfg, ",\n\"sched-time\" : \"%d:%d\"", schedstart.tm.tm_hour, schedstart.tm.tm_min);
	if (schedstop.enable)
		fprintf(fcfg, ",\n\"stop-time\" : \"%d:%d\"", schedstop.tm.tm_hour, schedstop.tm.tm_min);
	if (opt_socks_proxy && *opt_socks_proxy)
		fprintf(fcfg, ",\n\"socks-proxy\" : \"%s\"", json_escape(opt_socks_proxy));
	if (opt_devs_enabled) {
		fprintf(fcfg, ",\n\"device\" : \"");
		bool extra_devs = false;

		for (i = 0; i < MAX_DEVICES; i++) {
			if (devices_enabled[i]) {
				int startd = i;

				if (extra_devs)
					fprintf(fcfg, ",");
				while (i < MAX_DEVICES && devices_enabled[i + 1])
					++i;
				fprintf(fcfg, "%d", startd);
				if (i > startd)
					fprintf(fcfg, "-%d", i);
			}
		}
		fprintf(fcfg, "\"");
	}
	if (opt_removedisabled)
		fprintf(fcfg, ",\n\"remove-disabled\" : true");
	if (strcmp(opt_algorithm->name, "scrypt") != 0)
		fprintf(fcfg, ",\n\"algorithm\" : \"%s\"", json_escape(opt_algorithm->name));
	if (opt_api_allow)
		fprintf(fcfg, ",\n\"api-allow\" : \"%s\"", json_escape(opt_api_allow));
	if (strcmp(opt_api_mcast_addr, API_MCAST_ADDR) != 0)
		fprintf(fcfg, ",\n\"api-mcast-addr\" : \"%s\"", json_escape(opt_api_mcast_addr));
	if (strcmp(opt_api_mcast_code, API_MCAST_CODE) != 0)
		fprintf(fcfg, ",\n\"api-mcast-code\" : \"%s\"", json_escape(opt_api_mcast_code));
	if (*opt_api_mcast_des)
		fprintf(fcfg, ",\n\"api-mcast-des\" : \"%s\"", json_escape(opt_api_mcast_des));
	if (strcmp(opt_api_description, PACKAGE_STRING) != 0)
		fprintf(fcfg, ",\n\"api-description\" : \"%s\"", json_escape(opt_api_description));
	if (opt_api_groups)
		fprintf(fcfg, ",\n\"api-groups\" : \"%s\"", json_escape(opt_api_groups));

	fputs("\n}\n", fcfg);

	json_escape_free();
}


char *set_default_config(const char *arg)
{
	opt_set_charp(arg, &default_config);

	return NULL;
}

void default_save_file(char *filename)
{
	if (default_config && *default_config) {
		strcpy(filename, default_config);
		return;
	}

#if defined(unix) || defined(__APPLE__)
	if (getenv("HOME") && *getenv("HOME")) {
	        strcpy(filename, getenv("HOME"));
		strcat(filename, "/");
	}
	else
		strcpy(filename, "");
	strcat(filename, ".sgminer/");
	mkdir(filename, 0777);
#else
	strcpy(filename, "");
#endif
	strcat(filename, def_conf);
}

void load_default_config(void)
{
	cnfbuf = (char *)malloc(PATH_MAX);

	default_save_file(cnfbuf);

	if (!access(cnfbuf, R_OK))
		load_config(cnfbuf, NULL);
	else {
		free(cnfbuf);
		cnfbuf = NULL;
	}
}

char *set_algo(const char *arg)
{
	if ((json_array_index < 0) || (total_pools == 0)) {
		set_algorithm(opt_algorithm, arg);
		applog(LOG_INFO, "Set default algorithm to %s", opt_algorithm->name);
	} else {
		set_pool_algorithm(arg);
	}

	return NULL;
}

char *set_nfactor(const char *arg)
{
	if ((json_array_index < 0) || (total_pools == 0)) {
		set_algorithm_nfactor(opt_algorithm, (const uint8_t) atoi(arg));
		applog(LOG_INFO, "Set algorithm N-factor to %d (N to %d)",
		       opt_algorithm->nfactor, opt_algorithm->n);
	} else {
		set_pool_nfactor(arg);
	}

	return NULL;
}

char *set_api_allow(const char *arg)
{
	opt_set_charp(arg, &opt_api_allow);

	return NULL;
}

char *set_api_groups(const char *arg)
{
	opt_set_charp(arg, &opt_api_groups);

	return NULL;
}

char *set_api_description(const char *arg)
{
	opt_set_charp(arg, &opt_api_description);

	return NULL;
}

char *set_api_mcast_addr(const char *arg)
{
	opt_set_charp(arg, &opt_api_mcast_addr);

	return NULL;
}

char *set_api_mcast_code(const char *arg)
{
	opt_set_charp(arg, &opt_api_mcast_code);

	return NULL;
}

char *set_api_mcast_des(const char *arg)
{
	opt_set_charp(arg, &opt_api_mcast_des);

	return NULL;
}

char *set_null(const char __maybe_unused *arg)
{
	return NULL;
}

char *set_temp_cutoff(char *arg)
{
	int val;

	if (!(arg && arg[0]))
		return "Invalid parameters for set temp cutoff";
	val = atoi(arg);
	if (val < 0 || val > 200)
		return "Invalid value passed to set temp cutoff";
	temp_cutoff_str = arg;

	return NULL;
}

char* set_sharelog(char *arg)
{
	char *r = "";
	long int i = strtol(arg, &r, 10);

	if ((!*r) && i >= 0 && i <= INT_MAX) {
		sharelog_file = fdopen((int)i, "a");
		if (!sharelog_file)
			applog(LOG_ERR, "Failed to open fd %u for share log", (unsigned int)i);
	} else if (!strcmp(arg, "-")) {
		sharelog_file = stdout;
		if (!sharelog_file)
			applog(LOG_ERR, "Standard output missing for share log");
	} else {
		sharelog_file = fopen(arg, "a");
		if (!sharelog_file)
			applog(LOG_ERR, "Failed to open %s for share log", arg);
	}

	return NULL;
}

char *set_schedtime(const char *arg, struct schedtime *st)
{
	if (sscanf(arg, "%d:%d", &st->tm.tm_hour, &st->tm.tm_min) != 2)
		return "Invalid time set, should be HH:MM";
	if (st->tm.tm_hour > 23 || st->tm.tm_min > 59 || st->tm.tm_hour < 0 || st->tm.tm_min < 0)
		return "Invalid time set.";
	st->enable = true;
	return NULL;
}

char *set_pool_priority(char *arg)
{
	struct pool *pool = get_current_pool();

	applog(LOG_DEBUG, "Setting pool %i priority to %s", pool->pool_no, arg);
	opt_set_intval(arg, &pool->prio);

	return NULL;
}

char *set_pool_description(char *arg)
{
	struct pool *pool = get_current_pool();

	applog(LOG_DEBUG, "Setting pool %i description to %s", pool->pool_no, arg);
	opt_set_charp(arg, &pool->description);

	return NULL;
}

char *set_pass(const char *arg)
{
	struct pool *pool = get_current_pool();

	opt_set_charp(arg, &pool->rpc_pass);

	return NULL;
}

char *set_userpass(const char *arg)
{
	struct pool *pool = get_current_pool();
	char *updup;

	updup = strdup(arg);
	opt_set_charp(arg, &pool->rpc_userpass);
	pool->rpc_user = strtok(updup, ":");
	if (!pool->rpc_user)
		return "Failed to find : delimited user info";
	pool->rpc_pass = strtok(NULL, ":");
	if (!pool->rpc_pass)
		pool->rpc_pass = "";

	return NULL;
}

char *set_quota(char *arg)
{
	char *semicolon = strchr(arg, ';'), *url;
	size_t len, qlen;
	int quota;
	struct pool *pool;

	if (!semicolon)
		return "No semicolon separated quota;URL pair found";
	len = strlen(arg);
	*semicolon = '\0';
	qlen = strlen(arg);
	if (!qlen)
		return "No parameter for quota found";
	len -= qlen + 1;
	if (len < 1)
		return "No parameter for URL found";
	quota = atoi(arg);
	if (quota < 0)
		return "Invalid negative parameter for quota set";
	url = arg + qlen + 1;
	pool = add_url();
	setup_url(pool, url);
	pool->quota = quota;
	applog(LOG_INFO, "Setting %s to quota %d", get_pool_name(pool), pool->quota);
	adjust_quota_gcd();

	return NULL;
}

char *set_user(const char *arg)
{
	struct pool *pool = get_current_pool();

	opt_set_charp(arg, &pool->rpc_user);

	return NULL;
}

char *set_pool_state(char *arg)
{
	struct pool *pool = get_current_pool();

	applog(LOG_INFO, "Setting pool %s state to %s", get_pool_name(pool), arg);
	if (strcmp(arg, "disabled") == 0) {
		pool->state = POOL_DISABLED;
	} else if (strcmp(arg, "enabled") == 0) {
		pool->state = POOL_ENABLED;
	} else if (strcmp(arg, "hidden") == 0) {
		pool->state = POOL_HIDDEN;
	} else if (strcmp(arg, "rejecting") == 0) {
		pool->state = POOL_REJECTING;
	} else {
		pool->state = POOL_ENABLED;
	}

	return NULL;
}

char *set_url(char *arg)
{
	struct pool *pool = add_url();

	setup_url(pool, arg);
	return NULL;
}


char *set_pool_algorithm(const char *arg)
{
	struct pool *pool = get_current_pool();

	applog(LOG_DEBUG, "Setting pool %i algorithm to %s", pool->pool_no, arg);
	set_algorithm(&pool->algorithm, arg);

	return NULL;
}

char *set_pool_nfactor(const char *arg)
{
	struct pool *pool = get_current_pool();

	applog(LOG_DEBUG, "Setting pool %i N-factor to %s", pool->pool_no, arg);
	set_algorithm_nfactor(&pool->algorithm, (const uint8_t) atoi(arg));

	return NULL;
}

char *set_pool_name(char *arg)
{
	struct pool *pool = get_current_pool();

	applog(LOG_DEBUG, "Setting pool %i name to %s", pool->pool_no, arg);
	opt_set_charp(arg, &pool->name);

	return NULL;
}

char *set_poolname_deprecated(char *arg)
{
	applog(LOG_ERR, "Specifying pool name by --poolname is deprecated. Use --name instead.");
	set_pool_name(arg);

	return NULL;
}

char *set_balance(enum pool_strategy *strategy)
{
	*strategy = POOL_BALANCE;
	return NULL;
}

char *set_loadbalance(enum pool_strategy *strategy)
{
	*strategy = POOL_LOADBALANCE;
	return NULL;
}

char *set_rotate(const char *arg, int *i)
{
	pool_strategy = POOL_ROTATE;
	return set_int_range(arg, i, 0, 9999);
}

char *set_rr(enum pool_strategy *strategy)
{
	*strategy = POOL_ROUNDROBIN;
	return NULL;
}

char *set_int_range(const char *arg, int *i, int min, int max)
{
	char *err = opt_set_intval(arg, i);

	if (err)
		return err;

	if (*i < min || *i > max)
		return "Value out of range";

	return NULL;
}

char *set_int_0_to_9999(const char *arg, int *i)
{
	return set_int_range(arg, i, 0, 9999);
}

char *set_int_1_to_65535(const char *arg, int *i)
{
	return set_int_range(arg, i, 1, 65535);
}

char *set_int_0_to_10(const char *arg, int *i)
{
	return set_int_range(arg, i, 0, 10);
}

char *set_int_1_to_10(const char *arg, int *i)
{
	return set_int_range(arg, i, 1, 10);
}

void get_intrange(char *arg, int *val1, int *val2)
{
	if (sscanf(arg, "%d-%d", val1, val2) == 1)
		*val2 = *val1;
}

char *set_devices(char *arg)
{
	int i, val1 = 0, val2 = 0;
	char *nextptr;

	if (*arg) {
		if (*arg == '?') {
			opt_display_devs = true;
			return NULL;
		}
	} else
		return "Invalid device parameters";

	nextptr = strtok(arg, ",");
	if (nextptr == NULL)
		return "Invalid parameters for set devices";
	get_intrange(nextptr, &val1, &val2);
	if (val1 < 0 || val1 > MAX_DEVICES || val2 < 0 || val2 > MAX_DEVICES ||
	    val1 > val2) {
		return "Invalid value passed to set devices";
	}

	for (i = val1; i <= val2; i++) {
		devices_enabled[i] = true;
		opt_devs_enabled++;
	}

	while ((nextptr = strtok(NULL, ",")) != NULL) {
		get_intrange(nextptr, &val1, &val2);
		if (val1 < 0 || val1 > MAX_DEVICES || val2 < 0 || val2 > MAX_DEVICES ||
		val1 > val2) {
			return "Invalid value passed to set devices";
		}

		for (i = val1; i <= val2; i++) {
			devices_enabled[i] = true;
			opt_devs_enabled++;
		}
	}

	return NULL;
}

struct pool* get_current_pool()
{
	while ((json_array_index + 1) > total_pools)
		add_pool();

	if (json_array_index < 0) {
		if (!total_pools)
			add_pool();
		return pools[total_pools - 1];
	}

	return pools[json_array_index];
}

char *enable_debug(bool *flag)
{
	*flag = true;
	/* Turn on verbose output, too. */
	opt_log_output = true;
	return NULL;
}

extern const char *opt_argv0;

static char *opt_verusage_and_exit(const char *extra)
{
	printf("%s\n", packagename);
	printf("%s", opt_usage(opt_argv0, extra));
	fflush(stdout);
	exit(0);
}

char *display_devs(int *ndevs)
{
	*ndevs = 0;
	print_ndevs(ndevs);
	exit(*ndevs);
}

/* These options are available from config file or commandline */
static struct opt_table opt_config_table[] = {
	OPT_WITH_ARG("--algorithm",
		     set_algo, NULL, NULL,
		     "Set mining algorithm and most common defaults, default: scrypt"),
	OPT_WITH_ARG("--api-allow",
		     set_api_allow, NULL, NULL,
		     "Allow API access only to the given list of [G:]IP[/Prefix] addresses[/subnets]"),
	OPT_WITH_ARG("--api-description",
		     set_api_description, NULL, NULL,
		     "Description placed in the API status header, default: sgminer version"),
	OPT_WITH_ARG("--api-groups",
		     set_api_groups, NULL, NULL,
		     "API one letter groups G:cmd:cmd[,P:cmd:*...] defining the cmds a groups can use"),
	OPT_WITHOUT_ARG("--api-listen",
			opt_set_bool, &opt_api_listen,
			"Enable API, default: disabled"),
	OPT_WITHOUT_ARG("--api-mcast",
			opt_set_bool, &opt_api_mcast,
			"Enable API Multicast listener, default: disabled"),
	OPT_WITH_ARG("--api-mcast-addr",
		     set_api_mcast_addr, NULL, NULL,
		     "API Multicast listen address"),
	OPT_WITH_ARG("--api-mcast-code",
		     set_api_mcast_code, NULL, NULL,
		     "Code expected in the API Multicast message, don't use '-'"),
	OPT_WITH_ARG("--api-mcast-des",
		     set_api_mcast_des, NULL, NULL,
		     "Description appended to the API Multicast reply, default: ''"),
	OPT_WITH_ARG("--api-mcast-port",
		     set_int_1_to_65535, opt_show_intval, &opt_api_mcast_port,
		     "API Multicast listen port"),
	OPT_WITHOUT_ARG("--api-network",
			opt_set_bool, &opt_api_network,
			"Allow API (if enabled) to listen on/for any address, default: only 127.0.0.1"),
	OPT_WITH_ARG("--api-port",
		     set_int_1_to_65535, opt_show_intval, &opt_api_port,
		     "Port number of miner API"),
#ifdef HAVE_ADL
	OPT_WITHOUT_ARG("--auto-fan",
			opt_set_bool, &opt_autofan,
			"Automatically adjust all GPU fan speeds to maintain a target temperature"),
	OPT_WITHOUT_ARG("--auto-gpu",
			opt_set_bool, &opt_autoengine,
			"Automatically adjust all GPU engine clock speeds to maintain a target temperature"),
#endif
	OPT_WITHOUT_ARG("--balance",
		     set_balance, &pool_strategy,
		     "Change multipool strategy from failover to even share balance"),
#ifdef HAVE_CURSES
	OPT_WITHOUT_ARG("--compact",
			opt_set_bool, &opt_compact,
			"Use compact display without per device statistics"),
#endif
	OPT_WITHOUT_ARG("--debug|-D",
		     enable_debug, &opt_debug,
		     "Enable debug output"),
	OPT_WITH_ARG("--description",
		     set_pool_description, NULL, NULL,
		     "Pool description"),
	OPT_WITH_ARG("--device|-d",
		     set_devices, NULL, NULL,
	             "Select device to use, one value, range and/or comma separated (e.g. 0-2,4) default: all"),
	OPT_WITHOUT_ARG("--disable-rejecting",
			opt_set_bool, &opt_disable_pool,
			"Automatically disable pools that continually reject shares"),
	OPT_WITH_ARG("--expiry|-E",
		     set_int_0_to_9999, opt_show_intval, &opt_expiry,
		     "Upper bound on how many seconds after getting work we consider a share from it stale"),
	OPT_WITHOUT_ARG("--failover-only",
			opt_set_bool, &opt_fail_only,
			"Don't leak work to backup pools when primary pool is lagging"),
	OPT_WITH_ARG("--failover-switch-delay",
			set_int_1_to_65535, opt_show_intval, &opt_fail_switch_delay,
			"Delay in seconds before switching back to a failed pool"),
	OPT_WITHOUT_ARG("--fix-protocol",
			opt_set_bool, &opt_fix_protocol,
			"Do not redirect to a different getwork protocol (eg. stratum)"),
	OPT_WITH_ARG("--gpu-dyninterval",
		     set_int_1_to_65535, opt_show_intval, &opt_dynamic_interval,
		     "Set the refresh interval in ms for GPUs using dynamic intensity"),
	OPT_WITH_ARG("--gpu-platform",
		     set_int_0_to_9999, opt_show_intval, &opt_platform_id,
		     "Select OpenCL platform ID to use for GPU mining"),
#ifndef HAVE_ADL
	// gpu-threads can only be set per-card if ADL is available
	OPT_WITH_ARG("--gpu-threads|-g",
		     set_int_1_to_10, opt_show_intval, &opt_g_threads,
		     "Number of threads per GPU (1 - 10)"),
#else
	OPT_WITH_ARG("--gpu-threads|-g",
		     set_gpu_threads, NULL, NULL,
		     "Number of threads per GPU - one value or comma separated list (e.g. 1,2,1)"),
	OPT_WITH_ARG("--gpu-engine",
		     set_gpu_engine, NULL, NULL,
		     "GPU engine (over)clock range in Mhz - one value, range and/or comma separated list (e.g. 850-900,900,750-850)"),
	OPT_WITH_ARG("--gpu-fan",
		     set_gpu_fan, NULL, NULL,
		     "GPU fan percentage range - one value, range and/or comma separated list (e.g. 0-85,85,65)"),
	OPT_WITH_ARG("--gpu-map",
		     set_gpu_map, NULL, NULL,
		     "Map OpenCL to ADL device order manually, paired CSV (e.g. 1:0,2:1 maps OpenCL 1 to ADL 0, 2 to 1)"),
	OPT_WITH_ARG("--gpu-memclock",
		     set_gpu_memclock, NULL, NULL,
		     "Set the GPU memory (over)clock in Mhz - one value for all or separate by commas for per card"),
	OPT_WITH_ARG("--gpu-memdiff",
		     set_gpu_memdiff, NULL, NULL,
		     "Set a fixed difference in clock speed between the GPU and memory in auto-gpu mode"),
	OPT_WITH_ARG("--gpu-powertune",
		     set_gpu_powertune, NULL, NULL,
		     "Set the GPU powertune percentage - one value for all or separate by commas for per card"),
	OPT_WITHOUT_ARG("--gpu-reorder",
			opt_set_bool, &opt_reorder,
			"Attempt to reorder GPU devices according to PCI Bus ID"),
	OPT_WITH_ARG("--gpu-vddc",
		     set_gpu_vddc, NULL, NULL,
		     "Set the GPU voltage in Volts - one value for all or separate by commas for per card"),
#endif
	OPT_WITH_ARG("--lookup-gap",
		     set_lookup_gap, NULL, NULL,
		     "Set GPU lookup gap for scrypt mining, comma separated"),
#ifdef HAVE_CURSES
	OPT_WITHOUT_ARG("--incognito",
			opt_set_bool, &opt_incognito,
			"Do not display user name in status window"),
#endif
	OPT_WITH_ARG("--intensity|-I",
		     set_intensity, NULL, NULL,
		     "Intensity of GPU scanning (d or " MIN_INTENSITY_STR
		     " -> " MAX_INTENSITY_STR
		     ",default: d to maintain desktop interactivity), overridden by --xintensity or --rawintensity."),
	OPT_WITH_ARG("--xintensity|-X",
		     set_xintensity, NULL, NULL,
		     "Shader based intensity of GPU scanning (" MIN_XINTENSITY_STR " to "
			 MAX_XINTENSITY_STR "), overrides --intensity|-I, overridden by --rawintensity."),
	OPT_WITH_ARG("--rawintensity",
		     set_rawintensity, NULL, NULL,
		     "Raw intensity of GPU scanning (" MIN_RAWINTENSITY_STR " to "
			 MAX_RAWINTENSITY_STR "), overrides --intensity|-I and --xintensity|-X."),
	OPT_WITH_ARG("--kernel-path|-K",
		     opt_set_charp, opt_show_charp, &opt_kernel_path,
	             "Specify a path to where kernel files are"),
	OPT_WITH_ARG("--kernel|-k",
		     set_kernel, NULL, NULL,
		     "Override kernel to use - one value or comma separated"),
	OPT_WITHOUT_ARG("--load-balance",
			set_loadbalance, &pool_strategy,
			"Change multipool strategy from failover to quota based balance"),
	OPT_WITH_ARG("--log|-l",
		     set_int_0_to_9999, opt_show_intval, &opt_log_interval,
		     "Interval in seconds between log output"),
	OPT_WITHOUT_ARG("--log-show-date|-L",
			opt_set_bool, &opt_log_show_date,
			"Show date on every log line"),
	OPT_WITHOUT_ARG("--lowmem",
			opt_set_bool, &opt_lowmem,
			"Minimise caching of shares for low memory applications"),
#if defined(unix) || defined(__APPLE__)
	OPT_WITH_ARG("--monitor|-m",
		     opt_set_charp, NULL, &opt_stderr_cmd,
		     "Use custom pipe cmd for output messages"),
#endif // defined(unix)
	OPT_WITH_ARG("--name",
		     set_pool_name, NULL, NULL,
		     "Name of pool"),
	OPT_WITHOUT_ARG("--net-delay",
			opt_set_bool, &opt_delaynet,
			"Impose small delays in networking to not overload slow routers"),
	OPT_WITH_ARG("--nfactor",
		     set_nfactor, NULL, NULL,
		     "Override default scrypt N-factor parameter."),
#ifdef HAVE_ADL
	OPT_WITHOUT_ARG("--no-adl",
			opt_set_bool, &opt_noadl,
			"Disable the ATI display library used for monitoring and setting GPU parameters"),
#else
	OPT_WITHOUT_ARG("--no-adl",
			opt_set_bool, &opt_noadl, opt_hidden),
#endif
	OPT_WITHOUT_ARG("--no-pool-disable",
			opt_set_invbool, &opt_disable_pool,
			opt_hidden),
	OPT_WITHOUT_ARG("--no-client-reconnect",
			opt_set_invbool, &opt_disable_client_reconnect,
			"Disable 'client.reconnect' stratum functionality"),
	OPT_WITHOUT_ARG("--no-restart",
			opt_set_invbool, &opt_restart,
			"Do not attempt to restart GPUs that hang"),
	OPT_WITHOUT_ARG("--no-submit-stale",
			opt_set_invbool, &opt_submit_stale,
		        "Don't submit shares if they are detected as stale"),
	OPT_WITH_ARG("--pass|-p",
		     set_pass, NULL, NULL,
		     "Password for bitcoin JSON-RPC server"),
	OPT_WITHOUT_ARG("--per-device-stats",
			opt_set_bool, &want_per_device_stats,
			"Force verbose mode and output per-device statistics"),
	OPT_WITH_ARG("--poolname", /* TODO: Backward compatibility, to be removed. */
		     set_poolname_deprecated, NULL, NULL,
		     opt_hidden),
	OPT_WITH_ARG("--priority",
			 set_pool_priority, NULL, NULL,
			 "Pool priority"),
	OPT_WITHOUT_ARG("--protocol-dump|-P",
			opt_set_bool, &opt_protocol,
			"Verbose dump of protocol-level activities"),
	OPT_WITH_ARG("--queue|-Q",
		     set_int_0_to_9999, opt_show_intval, &opt_queue,
		     "Minimum number of work items to have queued (0+)"),
	OPT_WITHOUT_ARG("--quiet|-q",
			opt_set_bool, &opt_quiet,
			"Disable logging output, display status and errors"),
	OPT_WITH_ARG("--quota|-U",
		     set_quota, NULL, NULL,
		     "quota;URL combination for server with load-balance strategy quotas"),
	OPT_WITHOUT_ARG("--real-quiet",
			opt_set_bool, &opt_realquiet,
			"Disable all output"),
	OPT_WITHOUT_ARG("--remove-disabled",
		     opt_set_bool, &opt_removedisabled,
	         "Remove disabled devices entirely, as if they didn't exist"),
	OPT_WITH_ARG("--retries",
		     set_null, NULL, NULL,
		     opt_hidden),
	OPT_WITH_ARG("--retry-pause",
		     set_null, NULL, NULL,
		     opt_hidden),
	OPT_WITH_ARG("--rotate",
		     set_rotate, opt_show_intval, &opt_rotate_period,
		     "Change multipool strategy from failover to regularly rotate at N minutes"),
	OPT_WITHOUT_ARG("--round-robin",
		     set_rr, &pool_strategy,
		     "Change multipool strategy from failover to round robin on failure"),
	OPT_WITH_ARG("--scan-time|-s",
		     set_int_0_to_9999, opt_show_intval, &opt_scantime,
		     "Upper bound on time spent scanning current work, in seconds"),
	OPT_WITH_ARG("--sched-start",
		     set_schedtime, NULL, &schedstart,
		     "Set a time of day in HH:MM to start mining (a once off without a stop time)"),
	OPT_WITH_ARG("--sched-stop",
		     set_schedtime, NULL, &schedstop,
		     "Set a time of day in HH:MM to stop mining (will quit without a start time)"),
	OPT_WITH_ARG("--shaders",
		     set_shaders, NULL, NULL,
		     "GPU shaders per card for tuning scrypt, comma separated"),
	OPT_WITH_ARG("--sharelog",
		     set_sharelog, NULL, NULL,
		     "Append share log to file"),
	OPT_WITH_ARG("--shares",
		     opt_set_intval, NULL, &opt_shares,
		     "Quit after mining N shares (default: unlimited)"),
	OPT_WITH_ARG("--socks-proxy",
		     opt_set_charp, NULL, &opt_socks_proxy,
		     "Set socks4 proxy (host:port)"),
	OPT_WITH_ARG("--state",
		     set_pool_state, NULL, NULL,
		     "Specify pool state at startup (default: enabled)"),
#ifdef HAVE_SYSLOG_H
	OPT_WITHOUT_ARG("--syslog",
			opt_set_bool, &use_syslog,
			"Use system log for output messages (default: standard error)"),
#endif
#if defined(HAVE_LIBCURL) && defined(CURL_HAS_KEEPALIVE)
	OPT_WITH_ARG("--tcp-keepalive",
		     set_int_0_to_9999, opt_show_intval, &opt_tcp_keepalive,
		     "TCP keepalive packet idle time"),
#else
	OPT_WITH_ARG("--tcp-keepalive",
		     set_int_0_to_9999, opt_show_intval, &opt_tcp_keepalive,
			 opt_hidden),
#endif
#ifdef HAVE_ADL
	OPT_WITH_ARG("--temp-cutoff",
		     set_temp_cutoff, opt_show_intval, &opt_cutofftemp,
		     "Temperature which a device will be automatically disabled at, one value or comma separated list"),
	OPT_WITH_ARG("--temp-hysteresis",
		     set_int_1_to_10, opt_show_intval, &opt_hysteresis,
		     "Set how much the temperature can fluctuate outside limits when automanaging speeds"),
	OPT_WITH_ARG("--temp-overheat",
		     set_temp_overheat, opt_show_intval, &opt_overheattemp,
		     "Temperature which a device will be throttled at while automanaging fan and/or GPU, one value or comma separated list"),
	OPT_WITH_ARG("--temp-target",
		     set_temp_target, opt_show_intval, &opt_targettemp,
		     "Temperature which a device should stay at while automanaging fan and/or GPU, one value or comma separated list"),
#endif
#ifdef HAVE_CURSES
	OPT_WITHOUT_ARG("--text-only|-T",
			opt_set_invbool, &use_curses,
			"Disable ncurses formatted screen output"),
#else
	OPT_WITHOUT_ARG("--text-only|-T",
			opt_set_invbool, &use_curses,
			opt_hidden),
#endif
	OPT_WITH_ARG("--thread-concurrency",
		     set_thread_concurrency, NULL, NULL,
		     "Set GPU thread concurrency for scrypt mining, comma separated"),
	OPT_WITH_ARG("--url|-o",
		     set_url, NULL, NULL,
		     "URL for bitcoin JSON-RPC server"),
	OPT_WITH_ARG("--pool-algorithm",
		     set_pool_algorithm, NULL, NULL,
		     "Set algorithm for pool"),
	OPT_WITH_ARG("--pool-nfactor",
		     set_pool_nfactor, NULL, NULL,
		     "Set N-factor for pool"),
	OPT_WITH_ARG("--user|-u",
		     set_user, NULL, NULL,
		     "Username for bitcoin JSON-RPC server"),
	OPT_WITH_ARG("--vectors",
		     set_vector, NULL, NULL,
		     opt_hidden),
		     /* All current kernels only support vectors=1 */
		     /* "Override detected optimal vector (1, 2 or 4) - one value or comma separated list"), */
	OPT_WITHOUT_ARG("--verbose|-v",
			opt_set_bool, &opt_log_output,
			"Log verbose output to stderr as well as status output"),
	OPT_WITH_ARG("--worksize|-w",
		     set_worksize, NULL, NULL,
		     "Override detected optimal worksize - one value or comma separated list"),
	OPT_WITH_ARG("--userpass|-O",
		     set_userpass, NULL, NULL,
		     "Username:Password pair for bitcoin JSON-RPC server"),
	OPT_WITHOUT_ARG("--worktime",
			opt_set_bool, &opt_worktime,
			"Display extra work time debug information"),
	OPT_WITH_ARG("--pools",
			opt_set_bool, NULL, NULL, opt_hidden),
	OPT_ENDTABLE
};

/* These options are available from commandline only */
struct opt_table opt_cmdline_table[] = {
	OPT_WITH_ARG("--config|-c",
		     load_config, NULL, NULL,
		     "Load a JSON-format configuration file\n"
		     "See example.conf for an example configuration."),
	OPT_WITH_ARG("--default-config",
		     set_default_config, NULL, NULL,
		     "Specify the filename of the default config file\n"
		     "Loaded at start and used when saving without a name."),
	OPT_WITHOUT_ARG("--help|-h",
			opt_verusage_and_exit, NULL,
			"Print this message"),
	OPT_WITHOUT_ARG("--ndevs|-n",
			display_devs, &nDevs,
			"Display number of detected GPUs, OpenCL platform "
			"information, and exit"),
	OPT_WITHOUT_ARG("--version|-V",
			opt_version_and_exit, packagename,
			"Display version and exit"),
	OPT_ENDTABLE
};
