#ifndef WAF_SITE_LOG_H
#define WAF_SITE_LOG_H

#include "waf.h"

#define MAX_SITE_LOG_FILES 10
#define MAX_LOG_BUFFER_SIZE 8192

typedef struct {
    FILE *access_fp;
    FILE *error_fp;
    char access_path[512];
    char error_path[512];
    site_log_level_t level;
    log_format_t format;
    int enabled;
    int max_file_size;
    int max_files;
    long current_size;
    pthread_mutex_t lock;
} site_log_handle_t;

site_log_handle_t* site_log_init(waf_site_config_t *site);
void site_log_destroy(site_log_handle_t *handle);
int site_log_access(site_log_handle_t *handle, const char *client_ip, 
                   const char *method, const char *url, int status, 
                   long bytes_sent, const char *referer, const char *user_agent);
int site_log_error(site_log_handle_t *handle, site_log_level_t level, 
                  const char *message, ...);
int site_log_rotate(site_log_handle_t *handle);
const char* site_log_level_str(site_log_level_t level);
const char* log_format_str(log_format_t format);
int site_log_parse_format(const char *str, log_format_t *out);

#endif