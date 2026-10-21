#ifndef WAF_PERF_H
#define WAF_PERF_H

#include "waf.h"

#define PERF_STATS_INTERVAL 10000

unsigned long long get_timestamp_us(void);

typedef struct {
    unsigned long total_requests;
    unsigned long blocked_requests;
    unsigned long cached_requests;
    
    unsigned long long total_processing_time;
    unsigned long long max_processing_time;
    unsigned long long min_processing_time;
    
    unsigned long rules_check_count;
    unsigned long long rules_check_time;
    
    unsigned long ai_detection_count;
    unsigned long long ai_detection_time;
    
    unsigned long cache_hits;
    unsigned long cache_misses;
    
    unsigned long active_connections;
    unsigned long peak_connections;
} perf_stats_t;

typedef struct {
    int enabled;
    int cache_enabled;
    int async_enabled;
    
    int worker_processes;
    int worker_threads;
    
    int connection_pool_size;
    int keepalive_timeout;
    
    int request_cache_size;
    int request_cache_ttl;
    
    int rules_cache_enabled;
    int precompile_rules;
    
    perf_stats_t stats;
    
    pthread_mutex_t stats_mutex;
    pthread_t stats_thread;
} perf_config_t;

typedef struct {
    char key[256];
    char value[4096];
    time_t timestamp;
    int ttl;
} cache_entry_t;

typedef struct {
    cache_entry_t entries[10000];
    int count;
    pthread_mutex_t mutex;
} request_cache_t;

int perf_init(perf_config_t *config);
void perf_cleanup(perf_config_t *config);

void perf_start_request(http_request_t *req);
void perf_end_request(http_request_t *req, int blocked);

void perf_record_rules_check(long long time);
void perf_record_ai_detection(long long time);

void perf_cache_hit(const char *key);
void perf_cache_miss(const char *key);

void perf_increment_active_connections(void);
void perf_decrement_active_connections(void);

perf_stats_t* perf_get_stats(void);
void perf_reset_stats(void);

int request_cache_init(request_cache_t *cache);
void request_cache_cleanup(request_cache_t *cache);
int request_cache_get(request_cache_t *cache, const char *key, char *value, int max_len);
int request_cache_set(request_cache_t *cache, const char *key, const char *value, int ttl);
void request_cache_purge_expired(request_cache_t *cache);

#endif