#include "../include/waf_perf.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stddef.h>

static perf_config_t perf_config;
static request_cache_t request_cache;

unsigned long long get_timestamp_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

int perf_init(perf_config_t *config) {
    if (!config) return -1;
    
    memset(&perf_config, 0, sizeof(perf_config));
    perf_config.enabled = config->enabled;
    perf_config.cache_enabled = config->cache_enabled;
    perf_config.async_enabled = config->async_enabled;
    perf_config.worker_processes = config->worker_processes;
    perf_config.worker_threads = config->worker_threads;
    perf_config.connection_pool_size = config->connection_pool_size;
    perf_config.keepalive_timeout = config->keepalive_timeout;
    perf_config.request_cache_size = config->request_cache_size;
    perf_config.request_cache_ttl = config->request_cache_ttl;
    perf_config.rules_cache_enabled = config->rules_cache_enabled;
    perf_config.precompile_rules = config->precompile_rules;
    
    pthread_mutex_init(&perf_config.stats_mutex, NULL);
    
    request_cache_init(&request_cache);
    
    waf_log(LOG_LEVEL_INFO, "Performance module initialized");
    waf_log(LOG_LEVEL_INFO, "  Worker processes: %d", perf_config.worker_processes);
    waf_log(LOG_LEVEL_INFO, "  Worker threads: %d", perf_config.worker_threads);
    waf_log(LOG_LEVEL_INFO, "  Cache enabled: %s", perf_config.cache_enabled ? "yes" : "no");
    waf_log(LOG_LEVEL_INFO, "  Connection pool size: %d", perf_config.connection_pool_size);
    
    return 0;
}

void perf_cleanup(perf_config_t *config) {
    pthread_mutex_destroy(&perf_config.stats_mutex);
    request_cache_cleanup(&request_cache);
}

void perf_start_request(http_request_t *req) {
    if (!req || !perf_config.enabled) return;
    
    req->start_time = get_timestamp_us();
}

void perf_end_request(http_request_t *req, int blocked) {
    if (!req || !perf_config.enabled) return;
    
    unsigned long long end_time = get_timestamp_us();
    unsigned long long processing_time = end_time - req->start_time;
    
    pthread_mutex_lock(&perf_config.stats_mutex);
    
    perf_config.stats.total_requests++;
    
    if (blocked) {
        perf_config.stats.blocked_requests++;
    }
    
    perf_config.stats.total_processing_time += processing_time;
    
    if (processing_time > perf_config.stats.max_processing_time) {
        perf_config.stats.max_processing_time = processing_time;
    }
    
    if (perf_config.stats.min_processing_time == 0 || processing_time < perf_config.stats.min_processing_time) {
        perf_config.stats.min_processing_time = processing_time;
    }
    
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

void perf_record_rules_check(long long time) {
    pthread_mutex_lock(&perf_config.stats_mutex);
    perf_config.stats.rules_check_count++;
    perf_config.stats.rules_check_time += time;
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

void perf_record_ai_detection(long long time) {
    pthread_mutex_lock(&perf_config.stats_mutex);
    perf_config.stats.ai_detection_count++;
    perf_config.stats.ai_detection_time += time;
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

void perf_cache_hit(const char *key) {
    (void)key;
    pthread_mutex_lock(&perf_config.stats_mutex);
    perf_config.stats.cache_hits++;
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

void perf_cache_miss(const char *key) {
    (void)key;
    pthread_mutex_lock(&perf_config.stats_mutex);
    perf_config.stats.cache_misses++;
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

void perf_increment_active_connections(void) {
    pthread_mutex_lock(&perf_config.stats_mutex);
    perf_config.stats.active_connections++;
    if (perf_config.stats.active_connections > perf_config.stats.peak_connections) {
        perf_config.stats.peak_connections = perf_config.stats.active_connections;
    }
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

void perf_decrement_active_connections(void) {
    pthread_mutex_lock(&perf_config.stats_mutex);
    if (perf_config.stats.active_connections > 0) {
        perf_config.stats.active_connections--;
    }
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

perf_stats_t* perf_get_stats(void) {
    static perf_stats_t stats_copy;
    
    pthread_mutex_lock(&perf_config.stats_mutex);
    memcpy(&stats_copy, &perf_config.stats, sizeof(perf_stats_t));
    pthread_mutex_unlock(&perf_config.stats_mutex);
    
    return &stats_copy;
}

void perf_reset_stats(void) {
    pthread_mutex_lock(&perf_config.stats_mutex);
    memset(&perf_config.stats, 0, sizeof(perf_stats_t));
    pthread_mutex_unlock(&perf_config.stats_mutex);
}

int request_cache_init(request_cache_t *cache) {
    if (!cache) return -1;
    
    memset(cache, 0, sizeof(request_cache_t));
    pthread_mutex_init(&cache->mutex, NULL);
    
    return 0;
}

void request_cache_cleanup(request_cache_t *cache) {
    if (!cache) return;
    pthread_mutex_destroy(&cache->mutex);
}

int request_cache_get(request_cache_t *cache, const char *key, char *value, int max_len) {
    if (!cache || !key || !value) return -1;
    
    pthread_mutex_lock(&cache->mutex);
    
    request_cache_purge_expired(cache);
    
    for (int i = 0; i < cache->count; i++) {
        if (strcmp(cache->entries[i].key, key) == 0) {
            if (cache->entries[i].timestamp + cache->entries[i].ttl > time(NULL)) {
                strncpy(value, cache->entries[i].value, max_len - 1);
                value[max_len - 1] = '\0';
                pthread_mutex_unlock(&cache->mutex);
                perf_cache_hit(key);
                return 0;
            }
            break;
        }
    }
    
    pthread_mutex_unlock(&cache->mutex);
    perf_cache_miss(key);
    return -1;
}

int request_cache_set(request_cache_t *cache, const char *key, const char *value, int ttl) {
    if (!cache || !key || !value) return -1;
    
    pthread_mutex_lock(&cache->mutex);
    
    request_cache_purge_expired(cache);
    
    if (cache->count >= 10000) {
        for (int i = 0; i < cache->count - 1; i++) {
            cache->entries[i] = cache->entries[i + 1];
        }
        cache->count--;
    }
    
    cache_entry_t *entry = &cache->entries[cache->count++];
    strncpy(entry->key, key, sizeof(entry->key) - 1);
    strncpy(entry->value, value, sizeof(entry->value) - 1);
    entry->timestamp = time(NULL);
    entry->ttl = ttl;
    
    pthread_mutex_unlock(&cache->mutex);
    
    return 0;
}

void request_cache_purge_expired(request_cache_t *cache) {
    if (!cache) return;
    
    time_t now = time(NULL);
    int j = 0;
    
    for (int i = 0; i < cache->count; i++) {
        if (cache->entries[i].timestamp + cache->entries[i].ttl > now) {
            if (i != j) {
                cache->entries[j] = cache->entries[i];
            }
            j++;
        }
    }
    
    cache->count = j;
}