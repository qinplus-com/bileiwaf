#include "../include/waf_site_log.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

site_log_handle_t* site_log_init(waf_site_config_t *site) {
    if (!site || !site->log_config.enabled) {
        return NULL;
    }
    
    site_log_handle_t *handle = malloc(sizeof(site_log_handle_t));
    if (!handle) {
        waf_log(LOG_LEVEL_ERROR, "Failed to allocate site log handle");
        return NULL;
    }
    
    memset(handle, 0, sizeof(site_log_handle_t));
    
    strncpy(handle->access_path, site->log_config.access_log_path, sizeof(handle->access_path) - 1);
    strncpy(handle->error_path, site->log_config.error_log_path, sizeof(handle->error_path) - 1);
    handle->level = site->log_config.level;
    handle->format = site->log_config.format;
    handle->enabled = site->log_config.enabled;
    handle->max_file_size = site->log_config.max_file_size > 0 ? site->log_config.max_file_size : 100;
    handle->max_files = site->log_config.max_files > 0 ? site->log_config.max_files : 5;
    
    pthread_mutex_init(&handle->lock, NULL);
    
    if (handle->access_path[0]) {
        char *dir = strdup(handle->access_path);
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir(dir, 0755);
        }
        free(dir);
        
        handle->access_fp = fopen(handle->access_path, "a");
        if (!handle->access_fp) {
            waf_log(LOG_LEVEL_ERROR, "Failed to open access log: %s - %s", 
                    handle->access_path, strerror(errno));
        }
    }
    
    if (handle->error_path[0]) {
        char *dir = strdup(handle->error_path);
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir(dir, 0755);
        }
        free(dir);
        
        handle->error_fp = fopen(handle->error_path, "a");
        if (!handle->error_fp) {
            waf_log(LOG_LEVEL_ERROR, "Failed to open error log: %s - %s", 
                    handle->error_path, strerror(errno));
        }
    }
    
    waf_log(LOG_LEVEL_INFO, "Site log initialized for %s", site->domains[0]);
    if (handle->access_fp) {
        waf_log(LOG_LEVEL_INFO, "  Access log: %s", handle->access_path);
    }
    if (handle->error_fp) {
        waf_log(LOG_LEVEL_INFO, "  Error log: %s", handle->error_path);
    }
    
    return handle;
}

void site_log_destroy(site_log_handle_t *handle) {
    if (!handle) return;
    
    pthread_mutex_lock(&handle->lock);
    
    if (handle->access_fp) {
        fclose(handle->access_fp);
        handle->access_fp = NULL;
    }
    if (handle->error_fp) {
        fclose(handle->error_fp);
        handle->error_fp = NULL;
    }
    
    pthread_mutex_unlock(&handle->lock);
    pthread_mutex_destroy(&handle->lock);
    
    free(handle);
}

int site_log_rotate(site_log_handle_t *handle) {
    if (!handle) return -1;
    
    pthread_mutex_lock(&handle->lock);
    
    if (handle->access_fp) {
        fclose(handle->access_fp);
        
        char backup_path[1024];
        for (int i = handle->max_files - 1; i > 0; i--) {
            snprintf(backup_path, sizeof(backup_path), "%s.%d", handle->access_path, i);
            char prev_path[1024];
            snprintf(prev_path, sizeof(prev_path), "%s.%d", handle->access_path, i - 1);
            
            if (i == 1) {
                rename(handle->access_path, backup_path);
            } else {
                rename(prev_path, backup_path);
            }
        }
        
        handle->access_fp = fopen(handle->access_path, "a");
        handle->current_size = 0;
    }
    
    if (handle->error_fp) {
        fclose(handle->error_fp);
        
        char backup_path[1024];
        for (int i = handle->max_files - 1; i > 0; i--) {
            snprintf(backup_path, sizeof(backup_path), "%s.%d", handle->error_path, i);
            char prev_path[1024];
            snprintf(prev_path, sizeof(prev_path), "%s.%d", handle->error_path, i - 1);
            
            if (i == 1) {
                rename(handle->error_path, backup_path);
            } else {
                rename(prev_path, backup_path);
            }
        }
        
        handle->error_fp = fopen(handle->error_path, "a");
    }
    
    pthread_mutex_unlock(&handle->lock);
    
    return 0;
}

int site_log_access(site_log_handle_t *handle, const char *client_ip, 
                   const char *method, const char *url, int status, 
                   long bytes_sent, const char *referer, const char *user_agent) {
    if (!handle || !handle->enabled || !handle->access_fp) {
        return -1;
    }
    
    pthread_mutex_lock(&handle->lock);
    
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", tm);
    
    char log_line[4096];
    int len = 0;
    
    switch (handle->format) {
        case LOG_FORMAT_COMMON:
            len = snprintf(log_line, sizeof(log_line),
                         "%s - - [%s] \"%s %s HTTP/1.1\" %d %ld\n",
                         client_ip, time_str, method, url, status, bytes_sent);
            break;
            
        case LOG_FORMAT_COMBINED:
            len = snprintf(log_line, sizeof(log_line),
                         "%s - - [%s] \"%s %s HTTP/1.1\" %d %ld \"%s\" \"%s\"\n",
                         client_ip, time_str, method, url, status, bytes_sent,
                         referer ? referer : "-", user_agent ? user_agent : "-");
            break;
            
        case LOG_FORMAT_JSON:
            len = snprintf(log_line, sizeof(log_line),
                         "{\"time\":\"%s\",\"client_ip\":\"%s\",\"method\":\"%s\",\"url\":\"%s\",\"status\":%d,\"bytes_sent\":%ld,\"referer\":\"%s\",\"user_agent\":\"%s\"}\n",
                         time_str, client_ip, method, url, status, bytes_sent,
                         referer ? referer : "-", user_agent ? user_agent : "-");
            break;
            
        case LOG_FORMAT_CSV:
            len = snprintf(log_line, sizeof(log_line),
                         "%s,%s,%s,%s,%d,%ld,\"%s\",\"%s\"\n",
                         time_str, client_ip, method, url, status, bytes_sent,
                         referer ? referer : "", user_agent ? user_agent : "");
            break;
    }
    
    if (len > 0) {
        fwrite(log_line, 1, len, handle->access_fp);
        fflush(handle->access_fp);
        
        handle->current_size += len;
        long max_bytes = (long)handle->max_file_size * 1024 * 1024;
        if (handle->current_size > max_bytes) {
            site_log_rotate(handle);
        }
    }
    
    pthread_mutex_unlock(&handle->lock);
    
    return 0;
}

int site_log_error(site_log_handle_t *handle, site_log_level_t level, 
                  const char *message, ...) {
    if (!handle || !handle->enabled || !handle->error_fp) {
        return -1;
    }
    
    if (level < handle->level) {
        return 0;
    }
    
    pthread_mutex_lock(&handle->lock);
    
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    
    va_list args;
    va_start(args, message);
    
    char formatted_msg[4096];
    vsnprintf(formatted_msg, sizeof(formatted_msg), message, args);
    
    va_end(args);
    
    fprintf(handle->error_fp, "[%s] [%s] %s\n", 
            time_str, site_log_level_str(level), formatted_msg);
    fflush(handle->error_fp);
    
    pthread_mutex_unlock(&handle->lock);
    
    return 0;
}

const char* site_log_level_str(site_log_level_t level) {
    switch (level) {
        case LOG_LEVEL_SITE_DEBUG: return "DEBUG";
        case LOG_LEVEL_SITE_INFO:  return "INFO";
        case LOG_LEVEL_SITE_WARN:  return "WARN";
        case LOG_LEVEL_SITE_ERROR: return "ERROR";
        case LOG_LEVEL_SITE_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

const char* log_format_str(log_format_t format) {
    switch (format) {
        case LOG_FORMAT_COMMON:  return "common";
        case LOG_FORMAT_COMBINED: return "combined";
        case LOG_FORMAT_JSON:   return "json";
        case LOG_FORMAT_CSV:    return "csv";
        default: return "common";
    }
}

int site_log_parse_format(const char *str, log_format_t *out) {
    if (!str || !out) return -1;
    
    if (strcmp(str, "common") == 0) {
        *out = LOG_FORMAT_COMMON;
    } else if (strcmp(str, "combined") == 0) {
        *out = LOG_FORMAT_COMBINED;
    } else if (strcmp(str, "json") == 0) {
        *out = LOG_FORMAT_JSON;
    } else if (strcmp(str, "csv") == 0) {
        *out = LOG_FORMAT_CSV;
    } else {
        return -1;
    }
    
    return 0;
}