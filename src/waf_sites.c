#include "../include/waf.h"
#include "../include/waf_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_FATAL 4

static int waf_load_sites_from_file_old(waf_config_t *config, const char *filename);
static int waf_load_sites_from_file_ini(waf_config_t *config, const char *filename);
static int waf_load_site_from_ini(waf_config_t *config, const char *filename);

static char* json_skip_ws(char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static char* json_parse_string(char *p, char *out, size_t max_len) {
    if (*p != '"') return NULL;
    p++;
    
    size_t i = 0;
    while (*p != '"' && *p != '\0' && i < max_len - 1) {
        if (*p == '\\' && *(p+1) != '\0') {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 'r': out[i++] = '\r'; break;
                case 't': out[i++] = '\t'; break;
                case '\\': out[i++] = '\\'; break;
                case '"': out[i++] = '"'; break;
                default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    
    if (*p == '"') p++;
    out[i] = '\0';
    return p;
}

static char* json_find_key(char *p, const char *key) {
    p = json_skip_ws(p);
    while (*p != '\0') {
        if (*p == '{') {
            p++;
            p = json_skip_ws(p);
            continue;
        }
        if (*p == '}') {
            p++;
            p = json_skip_ws(p);
            continue;
        }
        if (*p == ',') {
            p++;
            p = json_skip_ws(p);
            continue;
        }
        if (*p == '"') {
            char current_key[256];
            p = json_parse_string(p, current_key, sizeof(current_key));
            if (p && strcmp(current_key, key) == 0) {
                p = json_skip_ws(p);
                if (*p == ':') {
                    p++;
                    p = json_skip_ws(p);
                    return p;
                }
            }
        }
        p++;
    }
    return NULL;
}

static int json_parse_int(char *p, int *out) {
    *out = 0;
    int sign = 1;
    
    if (*p == '-') {
        sign = -1;
        p++;
    }
    
    if (!isdigit((unsigned char)*p)) return -1;
    
    while (isdigit((unsigned char)*p)) {
        *out = *out * 10 + (*p - '0');
        p++;
    }
    
    *out *= sign;
    return 0;
}

static int json_parse_string_value(char *p, char *out, size_t max_len) {
    if (*p == '"') {
        p = json_parse_string(p, out, max_len);
        return p ? 0 : -1;
    }
    return -1;
}

static int json_parse_array_of_strings(char *p, char (*out)[256], int *count, int max_count) {
    if (*p != '[') return -1;
    p++;
    p = json_skip_ws(p);
    
    *count = 0;
    while (*p != ']' && *p != '\0') {
        if (*p == '"') {
            char str[256];
            p = json_parse_string(p, str, sizeof(str));
            if (!p) return -1;
            
            if (*count < max_count) {
                strncpy(out[*count], str, sizeof(out[0]) - 1);
                (*count)++;
            }
            
            p = json_skip_ws(p);
            if (*p == ',') p++;
            p = json_skip_ws(p);
        } else {
            p++;
        }
    }
    
    return 0;
}

static int json_parse_object(char *p, const char *key, char *out, size_t max_len) {
    char *value = json_find_key(p, key);
    if (!value) return -1;
    return json_parse_string_value(value, out, max_len);
}

static int json_parse_object_int(char *p, const char *key, int *out) {
    char *value = json_find_key(p, key);
    if (!value) return -1;
    return json_parse_int(value, out);
}

static int json_parse_object_bool(char *p, const char *key, int *out) {
    char *value = json_find_key(p, key);
    if (!value) return -1;
    
    if (strncmp(value, "true", 4) == 0) {
        *out = 1;
        return 0;
    } else if (strncmp(value, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    
    return json_parse_int(value, out);
}

static int waf_add_site_from_json(waf_config_t *config, char *site_json) {
    if (!config || !site_json) return -1;
    
    char domains[8][256] = {0};
    int domain_count = 0;
    
    if (json_parse_array_of_strings(json_find_key(site_json, "domains"), domains, &domain_count, 8) != 0) {
        waf_log(LOG_LEVEL_WARN, "Failed to parse domains from JSON");
        return -1;
    }
    
    if (domain_count == 0) {
        waf_log(LOG_LEVEL_WARN, "No domains found in site JSON");
        return -1;
    }
    
    char doc_root[512] = "/var/www/html";
    json_parse_object(site_json, "document_root", doc_root, sizeof(doc_root));
    
    char backend_host[256] = "127.0.0.1";
    int backend_port = 8080;
    
    char *backend_obj = json_find_key(site_json, "backend");
    if (backend_obj) {
        json_parse_object(backend_obj, "host", backend_host, sizeof(backend_host));
        json_parse_object_int(backend_obj, "port", &backend_port);
    }
    
    char domains_str[1024] = {0};
    for (int i = 0; i < domain_count; i++) {
        if (i > 0) strcat(domains_str, " ");
        strcat(domains_str, domains[i]);
    }
    
    int index = waf_add_site(config, domains_str, doc_root, backend_host, backend_port);
    if (index < 0) {
        return -1;
    }
    
    waf_site_config_t *site = &config->sites[index];
    site->domain_count = domain_count;
    for (int i = 0; i < domain_count; i++) {
        strncpy(site->domains[i], domains[i], sizeof(site->domains[0]) - 1);
    }
    
    char *ssl_obj = json_find_key(site_json, "ssl");
    if (ssl_obj) {
        json_parse_object(ssl_obj, "cert_file", site->cert_file, sizeof(site->cert_file));
        json_parse_object(ssl_obj, "key_file", site->key_file, sizeof(site->key_file));
    }
    
    json_parse_object(site_json, "language", site->language, sizeof(site->language));
    
    int translate_enabled = 0;
    if (json_parse_object_bool(site_json, "translate_enabled", &translate_enabled) == 0 && translate_enabled) {
        site->translate_enabled = 1;
        
        char service[32];
        if (json_parse_object(site_json, "translate_service", service, sizeof(service)) == 0) {
            if (strcmp(service, "baidu") == 0) {
                site->translate_service = TRANSLATE_BAIDU;
            } else if (strcmp(service, "api") == 0) {
                site->translate_service = TRANSLATE_API;
            } else {
                site->translate_service = TRANSLATE_GOOGLE;
            }
        }
        
        json_parse_object(site_json, "translate_api_key", site->translate_api_key, sizeof(site->translate_api_key));
        
        char *target_langs = json_find_key(site_json, "target_languages");
        if (target_langs) {
            json_parse_array_of_strings(target_langs, site->target_languages, &site->target_lang_count, 4);
        }
    }
    
    char *index_files = json_find_key(site_json, "index_files");
    if (index_files) {
        json_parse_array_of_strings(index_files, (char (*)[256])site->index_files, &site->index_count, 8);
    }
    
    char *proxy_pass = json_find_key(site_json, "proxy_pass");
    if (proxy_pass && *proxy_pass == '"') {
        site->proxy_enabled = 1;
        json_parse_string_value(proxy_pass, site->proxy_pass, sizeof(site->proxy_pass));
        json_parse_object_int(site_json, "proxy_timeout", &site->proxy_timeout);
    }
    
    return index;
}

int waf_load_sites_from_file_json(waf_config_t *config, const char *filename) {
    if (!config || !filename) return -1;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = (char*)malloc(size + 1);
    if (!content) {
        fclose(fp);
        return -1;
    }
    
    fread(content, 1, size, fp);
    content[size] = '\0';
    fclose(fp);
    
    char *sites_array = json_find_key(content, "sites");
    if (!sites_array) {
        free(content);
        return -1;
    }
    
    sites_array = json_skip_ws(sites_array);
    if (*sites_array != '[') {
        free(content);
        return -1;
    }
    
    char *p = sites_array + 1;
    p = json_skip_ws(p);
    
    while (*p != ']' && *p != '\0') {
        if (*p == '{') {
            char *end = p;
            int depth = 1;
            while (end && depth > 0) {
                end++;
                if (*end == '{') depth++;
                if (*end == '}') depth--;
            }
            
            if (end) {
                char site_json[4096];
                int len = end - p + 1;
                if (len > sizeof(site_json) - 1) len = sizeof(site_json) - 1;
                strncpy(site_json, p, len);
                site_json[len] = '\0';
                
                waf_add_site_from_json(config, site_json);
            }
            
            p = end + 1;
        } else {
            p++;
        }
        p = json_skip_ws(p);
        if (*p == ',') p++;
        p = json_skip_ws(p);
    }
    
    free(content);
    return 0;
}

int waf_add_site(waf_config_t *config, const char *domains_str, const char *doc_root,
                 const char *backend_host, int backend_port) {
    if (!config || !domains_str) return -1;
    
    if (config->site_count >= WAF_MAX_SITES) {
        waf_log(LOG_LEVEL_ERROR, "Maximum sites limit reached");
        return -1;
    }
    
    waf_site_config_t *site = &config->sites[config->site_count];
    memset(site, 0, sizeof(waf_site_config_t));
    
    if (doc_root && doc_root[0]) {
        strncpy(site->document_root, doc_root, sizeof(site->document_root) - 1);
    } else {
        strcpy(site->document_root, "/var/www/html");
    }
    
    if (backend_host && backend_host[0]) {
        strncpy(site->backend_host, backend_host, sizeof(site->backend_host) - 1);
    } else {
        strcpy(site->backend_host, config->backend_host);
    }
    
    site->backend_port = backend_port;
    
    site->enabled = 1;
    
    char domain_copy[512];
    strncpy(domain_copy, domains_str, sizeof(domain_copy) - 1);
    char *token = strtok(domain_copy, " ,\t\n");
    while (token && site->domain_count < 8) {
        strncpy(site->domains[site->domain_count], token, sizeof(site->domains[0]) - 1);
        site->domain_count++;
        token = strtok(NULL, " ,\t\n");
    }
    
    config->site_count++;
    
    waf_log(LOG_LEVEL_INFO, "Added site: %s -> %s:%d", 
            site->domains[0], site->backend_host, site->backend_port);
    
    return config->site_count - 1;
}

waf_site_config_t* waf_find_site(const waf_config_t *config, const char *domain) {
    if (!config || !domain) return NULL;
    
    char host[256];
    strncpy(host, domain, sizeof(host) - 1);
    
    char *port = strchr(host, ':');
    if (port) *port = '\0';

    /* 浏览器对 "dbask.cn." 这类带根尾点的 FQDN 会在 Host 头原样携带尾点，
     * 不去除则匹配不到站点、请求落到默认后端 */
    size_t hl = strlen(host);
    while (hl > 0 && host[hl - 1] == '.') host[--hl] = '\0';
    
    for (int i = 0; i < config->site_count; i++) {
        waf_site_config_t *site = &config->sites[i];
        if (!site->enabled) continue;
        
        for (int j = 0; j < site->domain_count; j++) {
            if (strcmp(site->domains[j], host) == 0) {
                return site;
            }
        }
    }
    
    return NULL;
}

int waf_remove_site(waf_config_t *config, const char *domain) {
    if (!config || !domain) return -1;
    
    for (int i = 0; i < config->site_count; i++) {
        waf_site_config_t *site = &config->sites[i];
        for (int j = 0; j < site->domain_count; j++) {
            if (strcmp(site->domains[j], domain) == 0) {
                site->enabled = 0;
                waf_log(LOG_LEVEL_INFO, "Disabled site: %s", domain);
                return 0;
            }
        }
    }
    
    return -1;
}

int waf_enable_site(waf_config_t *config, const char *domain) {
    if (!config || !domain) return -1;
    
    for (int i = 0; i < config->site_count; i++) {
        waf_site_config_t *site = &config->sites[i];
        for (int j = 0; j < site->domain_count; j++) {
            if (strcmp(site->domains[j], domain) == 0) {
                site->enabled = 1;
                waf_log(LOG_LEVEL_INFO, "Enabled site: %s", domain);
                return 0;
            }
        }
    }
    
    return -1;
}

int waf_sites_init(waf_config_t *config) {
    if (!config) return -1;
    
    config->site_count = 0;
    memset(config->sites, 0, sizeof(config->sites));
    
    return 0;
}

void waf_print_sites(const waf_config_t *config) {
    if (!config) return;
    
    waf_log(LOG_LEVEL_INFO, "Configured sites (%d):", config->site_count);
    
    for (int i = 0; i < config->site_count; i++) {
        waf_site_config_t *site = &config->sites[i];
        
        if (!site->enabled) continue;
        
        waf_log(LOG_LEVEL_INFO, "  - %s -> %s:%d", 
                site->domains[0], site->backend_host, site->backend_port);
        
        for (int j = 1; j < site->domain_count; j++) {
            waf_log(LOG_LEVEL_INFO, "    + %s", site->domains[j]);
        }
        
        if (site->cert_file[0] && site->key_file[0]) {
            waf_log(LOG_LEVEL_INFO, "      [SSL] %s", site->cert_file);
        }
    }
}

static int is_ini_format(const char *content) {
    if (strstr(content, "[") != NULL && strstr(content, "]") != NULL && 
        strstr(content, "=") != NULL) {
        return 1;
    }
    
    const char *p = content;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '#') {
        if (*p == '#') {
            while (*p != '\n' && *p != '\0') p++;
            if (*p == '\n') p++;
            continue;
        }
        p++;
    }
    
    return *p == '[';
}

static int parse_ini_section(FILE *fp, char *section, size_t section_size) {
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = waf_trim(line);
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strncpy(section, trimmed + 1, section_size - 1);
                return 1;
            }
        }
    }
    return 0;
}

static int parse_ini_key_value(const char *line, char *key, size_t key_size, char *value, size_t value_size) {
    char *eq = strchr(line, '=');
    if (!eq) return -1;
    
    *eq = '\0';
    strncpy(key, waf_trim(line), key_size - 1);
    strncpy(value, waf_trim(eq + 1), value_size - 1);
    
    return 0;
}

int waf_load_sites_from_file(waf_config_t *config, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    char first[128];
    size_t n = fread(first, 1, sizeof(first) - 1, fp);
    first[n] = '\0';
    fclose(fp);
    
    if (strchr(first, '{') != NULL) {
        return waf_load_sites_from_file_json(config, filename);
    }
    
    if (!is_ini_format(first)) {
        return waf_load_sites_from_file_old(config, filename);
    }
    
    return waf_load_sites_from_file_ini(config, filename);
}

int waf_load_sites_from_file_old(waf_config_t *config, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = waf_trim(line);
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        if (strncmp(trimmed, "site = ", 7) == 0) {
            char domain[128], doc_root[512], backend[256];
            int backend_port = 0;
            
            char *ptr = trimmed + 7;
            ptr = waf_trim(ptr);
            
            char *space = strchr(ptr, ' ');
            if (!space) continue;
            strncpy(domain, ptr, space - ptr);
            domain[space - ptr] = '\0';
            ptr = waf_trim(space + 1);
            
            space = strchr(ptr, ' ');
            if (!space) continue;
            strncpy(doc_root, ptr, space - ptr);
            doc_root[space - ptr] = '\0';
            ptr = waf_trim(space + 1);
            
            char *colon = strchr(ptr, ':');
            if (colon) {
                strncpy(backend, ptr, colon - ptr);
                backend[colon - ptr] = '\0';
                backend_port = atoi(colon + 1);
            } else {
                strncpy(backend, ptr, sizeof(backend) - 1);
                backend_port = config->backend_port;
            }
            
            int index = waf_add_site(config, domain, doc_root, backend, backend_port);
            
            if (index >= 0) {
                waf_site_config_t *site = &config->sites[index];
                if (fgets(line, sizeof(line), fp)) {
                    char *next_trimmed = waf_trim(line);
                    if (strncmp(next_trimmed, "cert = ", 7) == 0) {
                        char cert_path[512], key_path[512];
                        char *cert_ptr = next_trimmed + 7;
                        cert_ptr = waf_trim(cert_ptr);
                        
                        char *cert_space = strchr(cert_ptr, ' ');
                        if (cert_space) {
                            strncpy(cert_path, cert_ptr, cert_space - cert_ptr);
                            cert_path[cert_space - cert_ptr] = '\0';
                            char *key_ptr = waf_trim(cert_space + 1);
                            strncpy(key_path, key_ptr, sizeof(key_path) - 1);
                            key_path[sizeof(key_path) - 1] = '\0';
                            
                            strncpy(site->cert_file, cert_path, sizeof(site->cert_file) - 1);
                            strncpy(site->key_file, key_path, sizeof(site->key_file) - 1);
                        }
                    }
                }
            }
        }
    }
    
    fclose(fp);
    return 0;
}

int waf_load_sites_from_file_ini(waf_config_t *config, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_WARN, "Failed to open INI config file: %s", filename);
        return -1;
    }
    
    char section[64] = {0};
    char line[1024];
    /* sites include 目录与实际加载成功的 sites.conf 同目录（config/sites），
     * 保证便携发行包在任意 CWD / 无 WAF_HOME 时也不会误读 /opt/waf 下的生产配置；
     * filename 无目录分量时退回 CWD 下 sites/ */
    char sites_dir[512];
    {
        char cfg_copy[512];
        snprintf(cfg_copy, sizeof(cfg_copy), "%s", filename);
        char *slash = strrchr(cfg_copy, '/');
        if (slash) {
            *slash = '\0';
            snprintf(sites_dir, sizeof(sites_dir), "%s/sites", cfg_copy);
        } else {
            snprintf(sites_dir, sizeof(sites_dir), "sites");
        }
    }
    
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = waf_trim(line);
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strncpy(section, trimmed + 1, sizeof(section) - 1);
            }
            continue;
        }
        
        if (strcmp(section, "global") == 0) {
            char key[64], value[256];
            if (parse_ini_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                if (strcmp(key, "http_port") == 0) {
                    /* CLI -p 显式指定（WAF_HTTP_PORT）优先于站点全局配置 */
                    if (!getenv("WAF_HTTP_PORT"))
                        config->http_port = atoi(value);
                } else if (strcmp(key, "https_port") == 0) {
                    if (!getenv("WAF_HTTPS_PORT"))
                        config->https_port = atoi(value);
                } else if (strcmp(key, "worker_threads") == 0) {
                    if (!getenv("WAF_WORKER_THREADS"))
                        config->worker_threads = atoi(value);
                } else if (strcmp(key, "mode") == 0) {
                    if (strcmp(value, "learning") == 0) {
                        config->mode = WAF_MODE_LEARNING;
                    } else if (strcmp(value, "detection") == 0) {
                        config->mode = WAF_MODE_DETECTION;
                    } else {
                        config->mode = WAF_MODE_BLOCKING;
                    }
                } else if (strcmp(key, "log_dir") == 0) {
                    strncpy(config->log_dir, value, sizeof(config->log_dir) - 1);
                } else if (strcmp(key, "rules_dir") == 0) {
                    strncpy(config->rules_dir, value, sizeof(config->rules_dir) - 1);
                } else if (strcmp(key, "enable_cc_protection") == 0) {
                    config->enable_cc_protection = atoi(value);
                } else if (strcmp(key, "enable_api_protection") == 0) {
                    config->enable_api_protection = atoi(value);
                } else if (strcmp(key, "enable_bot_detection") == 0) {
                    config->enable_bot_detection = atoi(value);
                }
            }
        } else if (strcmp(section, "sites") == 0) {
            char key[64], value[256];
            if (parse_ini_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                if (strcmp(key, "site") == 0) {
                    char *status = strchr(value, ' ');
                    char site_file[256];
                    int enabled = 1;
                    
                    if (status) {
                        *status = '\0';
                        strncpy(site_file, value, sizeof(site_file) - 1);
                        char *status_val = waf_trim(status + 1);
                        if (strcmp(status_val, "disabled") == 0) {
                            enabled = 0;
                        }
                    } else {
                        strncpy(site_file, value, sizeof(site_file) - 1);
                    }
                    
                    char filepath[1024];
                    snprintf(filepath, sizeof(filepath), "%s/%s", sites_dir, site_file);
                    
                    if (enabled) {
                        waf_load_site_from_ini(config, filepath);
                    }
                }
            }
        } else if (strcmp(section, "cache") == 0) {
            char key[64], value[256];
            if (parse_ini_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                if (strcmp(key, "enabled") == 0) {
                    config->sites[0].optimization.cache_enabled = atoi(value);
                } else if (strcmp(key, "type") == 0) {
                    if (strcmp(value, "redis") == 0) {
                        config->sites[0].optimization.cache_type = CACHE_TYPE_REDIS;
                    } else if (strcmp(value, "memory") == 0) {
                        config->sites[0].optimization.cache_type = CACHE_TYPE_MEMORY;
                    } else {
                        config->sites[0].optimization.cache_type = CACHE_TYPE_FILE;
                    }
                } else if (strcmp(key, "max_size") == 0) {
                    config->sites[0].optimization.cache_max_size = atoi(value);
                } else if (strcmp(key, "expire_time") == 0) {
                    config->sites[0].optimization.cache_expire_time = atoi(value);
                }
            }
        }
    }
    
    fclose(fp);
    return 0;
}

int waf_load_site_from_ini(waf_config_t *config, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_WARN, "Failed to open site config: %s", filename);
        return -1;
    }
    
    char section[64] = {0};
    char line[1024];

    /* 支持多个 domain = 行或 domains = a,b 形式，累积为逗号分隔列表 */
    char domain[512] = {0};
    char doc_root[512] = {0};
    char backend_host[256] = {0};
    int backend_port = 0;
    /* 必须区分「未写 backend_port」与「显式 backend_port = 0」：
     * 前者回退全局默认后端（跟随 CLI -b / waf.conf）；
     * 后者表示纯静态站点——请求直接由 document_root 提供，不转发任何后端。
     * 旧实现把 0 当哨兵统一回退，导致 dbask.cn 等静态站点被错误代理到管理平面。 */
    int backend_port_set = 0;
    int enabled = 1;
    int cc_captcha = 0;
    
    char cert_file[512] = {0};
    char key_file[512] = {0};
    int ssl_enabled = 0;
    
    int cache_enabled = 0;
    char cache_type[32] = "memory";
    int cache_max_size = 256;
    int cache_expire_time = 7200;
    
    int gzip_enabled = 1;
    int gzip_min_length = 20;
    
    int csrf_protection = 1;
    int xss_protection = 1;
    int clickjacking_protection = 1;
    
    int translate_enabled = 0;
    char translate_service[32] = "google";
    char translate_api_key[256] = {0};
    char target_languages[128] = {0};
    
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = waf_trim(line);
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strncpy(section, trimmed + 1, sizeof(section) - 1);
            }
            continue;
        }
        
        char key[64], value[512];
        if (parse_ini_key_value(trimmed, key, sizeof(key), value, sizeof(value)) != 0) {
            continue;
        }
        
        if (strcmp(section, "site") == 0) {
            if (strcmp(key, "domain") == 0 || strcmp(key, "domains") == 0) {
                size_t len = strlen(domain);
                if (len > 0 && len < sizeof(domain) - 1) {
                    domain[len++] = ',';
                }
                strncat(domain, value, sizeof(domain) - len - 1);
            } else if (strcmp(key, "document_root") == 0) {
                strncpy(doc_root, value, sizeof(doc_root) - 1);
            } else if (strcmp(key, "backend_host") == 0) {
                strncpy(backend_host, value, sizeof(backend_host) - 1);
            } else if (strcmp(key, "backend_port") == 0) {
                backend_port = atoi(value);
                backend_port_set = 1;
            } else if (strcmp(key, "enabled") == 0) {
                enabled = atoi(value);
            } else if (strcmp(key, "cc_captcha") == 0) {
                /* CC 触发人机验证（v1.2.0）：默认 0 保持原直接封禁行为 */
                cc_captcha = atoi(value);
            }
        } else if (strcmp(section, "ssl") == 0) {
            if (strcmp(key, "enabled") == 0) {
                ssl_enabled = atoi(value);
            } else if (strcmp(key, "cert_file") == 0) {
                strncpy(cert_file, value, sizeof(cert_file) - 1);
            } else if (strcmp(key, "key_file") == 0) {
                strncpy(key_file, value, sizeof(key_file) - 1);
            }
        } else if (strcmp(section, "cache") == 0) {
            if (strcmp(key, "enabled") == 0) {
                cache_enabled = atoi(value);
            } else if (strcmp(key, "type") == 0) {
                strncpy(cache_type, value, sizeof(cache_type) - 1);
            } else if (strcmp(key, "max_size") == 0) {
                cache_max_size = atoi(value);
            } else if (strcmp(key, "expire_time") == 0) {
                cache_expire_time = atoi(value);
            }
        } else if (strcmp(section, "gzip") == 0) {
            if (strcmp(key, "enabled") == 0) {
                gzip_enabled = atoi(value);
            } else if (strcmp(key, "min_length") == 0) {
                gzip_min_length = atoi(value);
            }
        } else if (strcmp(section, "security") == 0) {
            if (strcmp(key, "csrf_protection") == 0) {
                csrf_protection = atoi(value);
            } else if (strcmp(key, "xss_protection") == 0) {
                xss_protection = atoi(value);
            } else if (strcmp(key, "clickjacking_protection") == 0) {
                clickjacking_protection = atoi(value);
            }
        } else if (strcmp(section, "translate") == 0) {
            if (strcmp(key, "enabled") == 0) {
                translate_enabled = atoi(value);
            } else if (strcmp(key, "service") == 0) {
                strncpy(translate_service, value, sizeof(translate_service) - 1);
            } else if (strcmp(key, "api_key") == 0) {
                strncpy(translate_api_key, value, sizeof(translate_api_key) - 1);
            } else if (strcmp(key, "target_languages") == 0) {
                strncpy(target_languages, value, sizeof(target_languages) - 1);
            }
        }
    }
    
    fclose(fp);
    
    if (!enabled || domain[0] == '\0') {
        return -1;
    }

    /* 仅当配置中完全没有 backend_port 键时才跟随全局默认（CLI -b / waf.conf）；
     * 显式 backend_port = 0 保留为 0：forward_to_backend 据此跳过转发，
     * 请求直接从站点自己的 document_root 提供静态内容。 */
    if (!backend_port_set) {
        backend_port = config->backend_port;
    }

    int index = waf_add_site(config, domain, doc_root, backend_host, backend_port);
    if (index < 0) {
        return -1;
    }
    
    waf_site_config_t *site = &config->sites[index];
    
    if (ssl_enabled && cert_file[0] && key_file[0]) {
        strncpy(site->cert_file, cert_file, sizeof(site->cert_file) - 1);
        strncpy(site->key_file, key_file, sizeof(site->key_file) - 1);
    }
    
    site->optimization.cache_enabled = cache_enabled;
    if (strcmp(cache_type, "redis") == 0) {
        site->optimization.cache_type = CACHE_TYPE_REDIS;
    } else if (strcmp(cache_type, "memory") == 0) {
        site->optimization.cache_type = CACHE_TYPE_MEMORY;
    } else {
        site->optimization.cache_type = CACHE_TYPE_FILE;
    }
    site->optimization.cache_max_size = cache_max_size;
    site->optimization.cache_expire_time = cache_expire_time;
    
    site->optimization.gzip_enabled = gzip_enabled;
    site->optimization.gzip_min_length = gzip_min_length;
    
    site->optimization.csrf_protection = csrf_protection;
    site->optimization.xss_protection = xss_protection;
    site->optimization.clickjacking_protection = clickjacking_protection;

    site->cc_captcha = cc_captcha;

    site->translate_enabled = translate_enabled;
    if (translate_enabled) {
        if (strcmp(translate_service, "baidu") == 0) {
            site->translate_service = TRANSLATE_BAIDU;
        } else if (strcmp(translate_service, "api") == 0) {
            site->translate_service = TRANSLATE_API;
        } else {
            site->translate_service = TRANSLATE_GOOGLE;
        }
        strncpy(site->translate_api_key, translate_api_key, sizeof(site->translate_api_key) - 1);
        
        char *lang = strtok(target_languages, ",");
        int lang_count = 0;
        while (lang && lang_count < 4) {
            strncpy(site->target_languages[lang_count], waf_trim(lang), sizeof(site->target_languages[0]) - 1);
            lang_count++;
            lang = strtok(NULL, ",");
        }
        site->target_lang_count = lang_count;
    }
    
    waf_log(LOG_LEVEL_INFO, "Loaded site config: %s -> %s:%d", domain, backend_host, backend_port);
    return index;
}

int waf_save_sites_to_file(const waf_config_t *config, const char *filename) {
    if (!config || !filename) return -1;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        waf_log(LOG_LEVEL_ERROR, "Failed to open site config for writing: %s", filename);
        return -1;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"sites\": [\n");
    
    for (int i = 0; i < config->site_count; i++) {
        const waf_site_config_t *site = &config->sites[i];
        if (!site->enabled) continue;
        
        fprintf(fp, "    {\n");
        
        fprintf(fp, "      \"domains\": [");
        for (int j = 0; j < site->domain_count; j++) {
            if (j > 0) fprintf(fp, ", ");
            fprintf(fp, "\"%s\"", site->domains[j]);
        }
        fprintf(fp, "],\n");
        
        fprintf(fp, "      \"document_root\": \"%s\",\n", site->document_root);
        
        if (site->index_count > 0) {
            fprintf(fp, "      \"index_files\": [");
            for (int j = 0; j < site->index_count; j++) {
                if (j > 0) fprintf(fp, ", ");
                fprintf(fp, "\"%s\"", site->index_files[j]);
            }
            fprintf(fp, "],\n");
        }
        
        if (site->language[0]) {
            fprintf(fp, "      \"language\": \"%s\",\n", site->language);
        }
        
        if (site->translate_enabled) {
            fprintf(fp, "      \"translate_enabled\": %d,\n", site->translate_enabled);
            const char *service_name = "google";
            if (site->translate_service == TRANSLATE_BAIDU) {
                service_name = "baidu";
            } else if (site->translate_service == TRANSLATE_API) {
                service_name = "api";
            }
            fprintf(fp, "      \"translate_service\": \"%s\",\n", service_name);
            if (site->translate_api_key[0]) {
                fprintf(fp, "      \"translate_api_key\": \"%s\",\n", site->translate_api_key);
            }
            if (site->target_lang_count > 0) {
                fprintf(fp, "      \"target_languages\": [");
                for (int j = 0; j < site->target_lang_count; j++) {
                    if (j > 0) fprintf(fp, ", ");
                    fprintf(fp, "\"%s\"", site->target_languages[j]);
                }
                fprintf(fp, "],\n");
            }
        }
        
        fprintf(fp, "      \"backend\": {\n");
        fprintf(fp, "        \"host\": \"%s\",\n", site->backend_host);
        fprintf(fp, "        \"port\": %d\n", site->backend_port);
        fprintf(fp, "      }");
        
        if (site->proxy_enabled && site->proxy_pass[0]) {
            fprintf(fp, ",\n");
            fprintf(fp, "      \"proxy_pass\": \"%s\",\n", site->proxy_pass);
            fprintf(fp, "      \"proxy_timeout\": %d", site->proxy_timeout);
        }
        
        if (site->cert_file[0] && site->key_file[0]) {
            fprintf(fp, ",\n");
            fprintf(fp, "      \"ssl\": {\n");
            fprintf(fp, "        \"cert_file\": \"%s\",\n", site->cert_file);
            fprintf(fp, "        \"key_file\": \"%s\"\n", site->key_file);
            fprintf(fp, "      }");
        }
        
        fprintf(fp, "\n    }");
        if (i < config->site_count - 1) fprintf(fp, ",");
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "  ],\n");
    fprintf(fp, "  \"defaults\": {\n");
    fprintf(fp, "    \"document_root\": \"/var/www/html\",\n");
    fprintf(fp, "    \"backend\": {\n");
    fprintf(fp, "      \"host\": \"127.0.0.1\",\n");
    fprintf(fp, "      \"port\": %d\n", config->backend_port);
    fprintf(fp, "    }\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    waf_log(LOG_LEVEL_INFO, "Saved site config to: %s", filename);
    return 0;
}

int waf_set_site_cert(waf_config_t *config, const char *domain, 
                      const char *cert_file, const char *key_file) {
    if (!config || !domain || !cert_file || !key_file) return -1;
    
    waf_site_config_t *site = waf_find_site(config, domain);
    if (!site) {
        waf_log(LOG_LEVEL_ERROR, "Site not found: %s", domain);
        return -1;
    }
    
    strncpy(site->cert_file, cert_file, sizeof(site->cert_file) - 1);
    strncpy(site->key_file, key_file, sizeof(site->key_file) - 1);
    
    waf_log(LOG_LEVEL_INFO, "Set certificate for %s: %s", domain, cert_file);
    return 0;
}

int waf_load_sites_from_directory(waf_config_t *config, const char *dirpath) {
    if (!config || !dirpath) return -1;
    
    DIR *dir = opendir(dirpath);
    if (!dir) {
        waf_log(LOG_LEVEL_WARN, "Failed to open directory: %s", dirpath);
        return -1;
    }
    
    struct dirent *entry;
    int count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) continue;
        
        size_t len = strlen(entry->d_name);
        if (len < 5) continue;
        
        if (strcmp(entry->d_name + len - 5, ".json") == 0 ||
            strcmp(entry->d_name + len - 5, ".conf") == 0) {
            
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
            
            if (strcmp(entry->d_name + len - 5, ".json") == 0) {
                if (waf_load_sites_from_file(config, filepath) == 0) {
                    count++;
                    waf_log(LOG_LEVEL_INFO, "Loaded site config: %s", filepath);
                }
            } else {
                if (waf_load_site_from_ini(config, filepath) == 0) {
                    count++;
                    waf_log(LOG_LEVEL_INFO, "Loaded site config: %s", filepath);
                }
            }
        }
    }
    
    closedir(dir);
    waf_log(LOG_LEVEL_INFO, "Loaded %d site configs from directory: %s", count, dirpath);
    return count;
}

int waf_import_conf_file(waf_config_t *config, const char *filename) {
    if (!config || !filename) return -1;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        waf_log(LOG_LEVEL_WARN, "Failed to open conf file: %s", filename);
        return -1;
    }
    
    char domains[512] = {0};
    char doc_root[512] = {0};
    char backend_host[256] = {0};
    int backend_port = 0;
    char proxy_pass[512] = {0};
    int proxy_timeout = 30;
    char cert_file[512] = {0};
    char key_file[512] = {0};
    char index_files[8][128] = {0};
    int index_count = 0;
    char language[16] = {0};
    
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = waf_trim(line);
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        if (strncmp(trimmed, "server_name ", 12) == 0) {
            strncpy(domains, trimmed + 12, sizeof(domains) - 1);
            waf_trim(domains);
        }
        else if (strncmp(trimmed, "root ", 5) == 0) {
            strncpy(doc_root, trimmed + 5, sizeof(doc_root) - 1);
            waf_trim(doc_root);
        }
        else if (strncmp(trimmed, "proxy_pass ", 11) == 0) {
            strncpy(proxy_pass, trimmed + 11, sizeof(proxy_pass) - 1);
            waf_trim(proxy_pass);
        }
        else if (strncmp(trimmed, "proxy_timeout ", 14) == 0) {
            proxy_timeout = atoi(trimmed + 14);
        }
        else if (strncmp(trimmed, "index ", 6) == 0) {
            char *ptr = trimmed + 6;
            char *token = strtok(ptr, " \t;");
            while (token && index_count < 8) {
                strncpy(index_files[index_count], token, sizeof(index_files[0]) - 1);
                index_count++;
                token = strtok(NULL, " \t;");
            }
        }
        else if (strncmp(trimmed, "ssl_certificate ", 16) == 0) {
            strncpy(cert_file, trimmed + 16, sizeof(cert_file) - 1);
            waf_trim(cert_file);
        }
        else if (strncmp(trimmed, "ssl_certificate_key ", 20) == 0) {
            strncpy(key_file, trimmed + 20, sizeof(key_file) - 1);
            waf_trim(key_file);
        }
        else if (strncmp(trimmed, "set $lang ", 10) == 0) {
            strncpy(language, trimmed + 10, sizeof(language) - 1);
            waf_trim(language);
        }
    }
    
    fclose(fp);
    
    if (domains[0] == '\0') {
        waf_log(LOG_LEVEL_WARN, "No server_name found in conf file: %s", filename);
        return -1;
    }
    
    int index = waf_add_site(config, domains, doc_root, backend_host, backend_port);
    if (index < 0) {
        return -1;
    }
    
    waf_site_config_t *site = &config->sites[index];
    
    if (proxy_pass[0]) {
        site->proxy_enabled = 1;
        strncpy(site->proxy_pass, proxy_pass, sizeof(site->proxy_pass) - 1);
        site->proxy_timeout = proxy_timeout;
    }
    
    if (cert_file[0] && key_file[0]) {
        strncpy(site->cert_file, cert_file, sizeof(site->cert_file) - 1);
        strncpy(site->key_file, key_file, sizeof(site->key_file) - 1);
    }
    
    if (index_count > 0) {
        site->index_count = index_count;
        for (int i = 0; i < index_count; i++) {
            strncpy(site->index_files[i], index_files[i], sizeof(site->index_files[0]) - 1);
        }
    }
    
    if (language[0]) {
        strncpy(site->language, language, sizeof(site->language) - 1);
    }
    
    return 0;
}

int waf_generate_site_config(const char *domain, const char *doc_root, const char *output_dir) {
    if (!domain || !output_dir) return -1;
    
    char filename[512];
    snprintf(filename, sizeof(filename), "%s/%s.conf", output_dir, domain);
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create config file: %s", filename);
        return -1;
    }
    
    fprintf(fp, "# Site Configuration for %s\n", domain);
    fprintf(fp, "\n");
    fprintf(fp, "[site]\n");
    fprintf(fp, "domain = %s\n", domain);
    fprintf(fp, "document_root = %s\n", doc_root ? doc_root : "/var/www/html");
    fprintf(fp, "backend_host = 127.0.0.1\n");
    fprintf(fp, "backend_port = 8080\n");
    fprintf(fp, "enabled = 1\n");
    fprintf(fp, "\n");
    fprintf(fp, "[ssl]\n");
    fprintf(fp, "enabled = 0\n");
    fprintf(fp, "cert_file = \n");
    fprintf(fp, "key_file = \n");
    fprintf(fp, "\n");
    fprintf(fp, "[logging]\n");
    fprintf(fp, "enabled = 0\n");
    fprintf(fp, "level = info\n");
    fprintf(fp, "access_log = logs/%s/access.log\n", domain);
    fprintf(fp, "error_log = logs/%s/error.log\n", domain);
    fprintf(fp, "format = combined\n");
    fprintf(fp, "max_file_size = 100\n");
    fprintf(fp, "max_files = 7\n");
    fprintf(fp, "\n");
    fprintf(fp, "[optimization]\n");
    fprintf(fp, "worker_processes = 4\n");
    fprintf(fp, "worker_threads = 8\n");
    fprintf(fp, "max_connections = 2000\n");
    fprintf(fp, "connection_timeout = 60\n");
    fprintf(fp, "keepalive_timeout = 120\n");
    fprintf(fp, "\n");
    fprintf(fp, "[cache]\n");
    fprintf(fp, "enabled = 0\n");
    fprintf(fp, "type = memory\n");
    fprintf(fp, "max_size = 256\n");
    fprintf(fp, "expire_time = 7200\n");
    fprintf(fp, "\n");
    fprintf(fp, "[request_limit]\n");
    fprintf(fp, "enabled = 0\n");
    fprintf(fp, "rate = 500\n");
    fprintf(fp, "burst = 1000\n");
    fprintf(fp, "\n");
    fprintf(fp, "[gzip]\n");
    fprintf(fp, "enabled = 1\n");
    fprintf(fp, "min_length = 20\n");
    fprintf(fp, "\n");
    fprintf(fp, "[security]\n");
    fprintf(fp, "csrf_protection = 1\n");
    fprintf(fp, "xss_protection = 1\n");
    fprintf(fp, "clickjacking_protection = 1\n");
    fprintf(fp, "\n");
    fprintf(fp, "[translate]\n");
    fprintf(fp, "enabled = 0\n");
    fprintf(fp, "service = google\n");
    fprintf(fp, "api_key = \n");
    fprintf(fp, "target_languages = en-US,ja-JP,ko-KR\n");
    
    fclose(fp);
    
    waf_log(LOG_LEVEL_INFO, "Generated site config: %s", filename);
    return 0;
}
