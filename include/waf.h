#ifndef WAF_H
#define WAF_H

#include "waf_common.h"
#include "waf_ai.h"

#ifndef WAF_VERSION
#define WAF_VERSION "0.0.1"
#endif

/* configure --prefix 注入（waf_config.h，-include 提前生效）；
 * 未走 configure 的裸编译回退到默认安装根 */
#ifndef WAF_PREFIX
#define WAF_PREFIX "/opt/bileiwaf"
#endif
/* configure --detection-mode 注入的编译期默认检测模式；
 * 未走 configure 的裸编译回退到 auto（AI 未就绪时自动回退规则兜底） */
#ifndef WAF_DEFAULT_DETECTION_MODE
#define WAF_DEFAULT_DETECTION_MODE DETECTION_MODE_AUTO
#endif
#define WAF_DEFAULT_HTTP_PORT 8080
#define WAF_DEFAULT_HTTPS_PORT 8444
#define WAF_DEFAULT_BACKEND_HOST "127.0.0.1"
#define WAF_DEFAULT_BACKEND_PORT 8080
#define WAF_WORKER_THREADS 4
#define WAF_MAX_CONNECTIONS 10000
#define WAF_MAX_SITES 32
#define WAF_MAX_LISTENERS 32

/* 日志轮转默认策略：单文件 50MB 触发轮转，归档保留 30 天 */
#define WAF_DEFAULT_LOG_ROTATE_MB  50
#define WAF_DEFAULT_LOG_RETENTION  30

/* 翻译服务类型 */
typedef enum {
    TRANSLATE_GOOGLE,
    TRANSLATE_BAIDU,
    TRANSLATE_API
} translate_service_t;

/* 动态语言运行时类型 */
typedef enum {
    RUNTIME_NONE = 0,
    RUNTIME_PHP_FPM,        /* PHP-FPM FastCGI */
    RUNTIME_NODE_JS,        /* Node.js HTTP */
    RUNTIME_PYTHON,         /* Python WSGI */
    RUNTIME_RUBY,           /* Ruby Rack */
    RUNTIME_GO,             /* Go net/http */
    RUNTIME_JAVA,           /* Java Servlet */
    RUNTIME_STATIC,         /* 静态文件服务 */
    RUNTIME_PROXY           /* 通用反向代理 */
} runtime_type_t;

/* 协议类型 */
typedef enum {
    PROTOCOL_HTTP11 = 0,
    PROTOCOL_FASTCGI,
    PROTOCOL_WEBSOCKET,
    PROTOCOL_HTTP2,
    PROTOCOL_AJP13
} protocol_type_t;

/* PHP-FPM 配置 */
typedef struct {
    char socket_path[256];       /* Unix socket 路径 */
    char host[256];              /* TCP 连接主机 */
    int port;                    /* TCP 连接端口 */
    int fastcgi_index;          /* SCRIPT_FILENAME */
    char script_filename[512];    /* 脚本文件路径 */
    char document_root[512];      /* 文档根目录 */
    int authoritative;           /* 是否强制使用脚本 */
} php_fpm_config_t;

/* 动态语言运行时配置 */
typedef struct {
    runtime_type_t type;         /* 运行时类型 */
    protocol_type_t protocol;    /* 协议类型 */
    char executable_path[512];   /* 运行时执行路径 */
    char app_root[512];          /* 应用根目录 */
    char startup_script[256];   /* 启动脚本 */
    int port;                    /* 监听端口 */
    int workers;                 /* 工作进程数 */
    int timeout;                 /* 请求超时时间 */
    char env_vars[16][128];      /* 环境变量 */
    int env_count;
    /* PHP-FPM 特定配置 */
    php_fpm_config_t php_fpm;
    /* 通用反向代理配置 */
    char upstream_host[256];
    int upstream_port;
    int keepalive_connections;
} runtime_config_t;

/* 日志级别 */
typedef enum {
    LOG_LEVEL_SITE_DEBUG = 0,
    LOG_LEVEL_SITE_INFO,
    LOG_LEVEL_SITE_WARN,
    LOG_LEVEL_SITE_ERROR,
    LOG_LEVEL_SITE_FATAL
} site_log_level_t;

/* 日志格式类型 */
typedef enum {
    LOG_FORMAT_COMMON,        /* Common Log Format */
    LOG_FORMAT_COMBINED,      /* Combined Log Format */
    LOG_FORMAT_JSON,          /* JSON 格式 */
    LOG_FORMAT_CSV            /* CSV 格式 */
} log_format_t;

/* 站点日志配置 */
typedef struct {
    int enabled;              /* 是否启用站点独立日志 */
    site_log_level_t level;   /* 日志级别 */
    char access_log_path[512];/* 访问日志路径 */
    char error_log_path[512]; /* 错误日志路径 */
    log_format_t format;      /* 日志格式 */
    int log_to_console;       /* 是否输出到控制台 */
    int max_file_size;        /* 日志文件最大大小(MB) */
    int max_files;            /* 最大保留日志文件数 */
    int buffer_size;          /* 日志缓冲区大小 */
} site_log_config_t;

/* 缓存类型 */
typedef enum {
    CACHE_TYPE_FILE,          /* 文件缓存 */
    CACHE_TYPE_MEMORY,        /* 内存缓存 */
    CACHE_TYPE_REDIS          /* Redis缓存 */
} cache_type_t;

/* 站点优化配置 */
typedef struct {
    /* 进程/线程配置 */
    int worker_processes;      /* 工作进程数 */
    int worker_threads;        /* 每个进程的线程数 */
    int max_connections;       /* 最大连接数 */
    int connection_timeout;    /* 连接超时时间(秒) */
    int keepalive_timeout;     /* Keep-Alive超时时间(秒) */
    
    /* 缓存配置 */
    int cache_enabled;        /* 是否启用缓存 */
    cache_type_t cache_type;   /* 缓存类型 */
    int cache_max_size;       /* 缓存最大大小(MB) */
    int cache_expire_time;    /* 缓存过期时间(秒) */
    char cache_redis_host[256];/* Redis主机 */
    int cache_redis_port;     /* Redis端口 */
    
    /* 请求限制 */
    int request_limit_enabled; /* 是否启用请求限制 */
    int request_limit_rate;   /* 请求速率限制(每秒) */
    int request_limit_burst;  /* 请求突发限制 */
    
    /* 压缩配置 */
    int gzip_enabled;         /* 是否启用gzip压缩 */
    int gzip_min_length;      /* 最小压缩长度 */
    char gzip_types[32][64];  /* 压缩类型 */
    int gzip_types_count;
    
    /* 安全配置 */
    int csrf_protection;      /* CSRF保护 */
    int xss_protection;       /* XSS保护 */
    int clickjacking_protection; /* 点击劫持保护 */
} site_optimization_config_t;

/* 站点配置结构 */
typedef struct {
    char domains[8][256];  /* 支持多个域名 */
    int domain_count;
    char document_root[512];
    char index_files[8][128];  /* 默认首页文件 */
    int index_count;
    char language[16];  /* 站点语言 */
    /* 机器翻译配置 */
    int translate_enabled;  /* 是否启用翻译 */
    translate_service_t translate_service;  /* 翻译服务类型 */
    char translate_api_key[256];  /* API密钥 */
    char target_languages[4][16];  /* 目标语言列表 */
    int target_lang_count;  /* 目标语言数量 */
    /* 后端服务器配置 */
    char backend_host[256];
    int backend_port;
    /* 反向代理配置 */
    int proxy_enabled;
    char proxy_pass[512];
    int proxy_timeout;
    /* SSL证书路径 */
    char cert_file[512];
    char key_file[512];
    int enabled;
    /* CC 人机验证：开启后非白名单 IP 触发 CC 阈值先发 /waf-captcha 挑战，
     * 验证通过发放放行 cookie（有效期 = CC block_duration）；默认关闭 */
    int cc_captcha;
    /* 动态语言运行时配置 */
    runtime_config_t runtime;
    /* 站点独立日志配置 */
    site_log_config_t log_config;
    /* 站点优化配置 */
    site_optimization_config_t optimization;
} waf_site_config_t;

/* 监听端口信息 */
typedef struct {
    int fd;
    int port;
    int is_https;
} waf_listener_t;

typedef struct {
    int http_port;
    int https_port;
    char backend_host[256];
    int backend_port;
    int worker_threads;
    int max_connections;
    waf_mode_t mode;
    detection_mode_t detection_mode;
    /* AI配置 */
    ai_ensemble_type_t ai_ensemble;
    double ai_threshold;
    double ai_ensemble_threshold;
    double ai_cnn_weight;          /* v3.0：可选覆盖融合校准的 w_cnn（0=沿用校准值） */
    double ai_model_weights[MAX_MODELS];
    char ai_whitelist_domains[512];
    /* AI 驱动：影子模式与自主学习护栏 */
    int ai_shadow_mode;
    int ai_auto_learn;
    int ai_guard_enabled;
    int ai_guard_min_occ;
    int ai_guard_min_conf;
    int ai_guard_max_rules;
    int ai_guard_max_white_fp;
    char ai_white_list[512];
    char ai_learned_rules[512];
    char cert_file[512];
    char key_file[512];
    char rules_dir[512];
    char log_dir[512];
    char error_404_page[1024];   /* 自定义 404 页面文件（相对 WAF_HOME 或绝对路径），空则用默认演示页 */
    char blocklist_file[512];
    char whitelist_file[512];
    int ssl_enabled;
    int log_level;
    int log_rotate_size_mb;   /* 单个日志文件轮转阈值（MB），0=不轮转 */
    int log_retention_days;   /* 轮转归档保留天数，0=永久保留 */
    int request_timeout;
    int keepalive_timeout;
    int max_body_size;
    int enable_cc_protection;
    int enable_api_protection;
    int enable_bot_detection;
    int auto_add_www;
    /* 站点配置 */
    waf_site_config_t sites[WAF_MAX_SITES];
    int site_count;
    /* 监听端口 */
    waf_listener_t listeners[WAF_MAX_LISTENERS];
    int listener_count;
} waf_config_t;

typedef struct {
    int listen_fd;
    int backend_fd;
    http_request_t request;
    http_response_t response;
    waf_result_t result;
    struct sockaddr_in client_addr;
    time_t start_time;
    int ssl;
} waf_context_t;

typedef struct {
    void (*init)(waf_config_t *config);
    int (*process)(waf_context_t *ctx);
    void (*destroy)(void);
} waf_module_t;

int waf_init(waf_config_t *config);
int waf_start(void);
void waf_stop(void);
int waf_process_request(waf_context_t *ctx);
waf_config_t* waf_get_config(void);

/* 站点配置管理函数 */
int waf_sites_init(waf_config_t *config);
int waf_add_site(waf_config_t *config, const char *domains_str, const char *doc_root,
                 const char *backend_host, int backend_port);
waf_site_config_t* waf_find_site(const waf_config_t *config, const char *host_header);
int waf_load_sites_from_file(waf_config_t *config, const char *filename);
int waf_load_sites_from_dir(waf_config_t *config, const char *dirpath);
int waf_import_conf_file(waf_config_t *config, const char *filename);
int waf_save_sites_to_file(const waf_config_t *config, const char *filename);
int waf_save_site_to_file(const waf_site_config_t *site, const char *filename);
int waf_set_site_cert(waf_config_t *config, const char *domain, 
                      const char *cert_file, const char *key_file);
void waf_print_sites(const waf_config_t *config);

/* 监听端口管理 */
int waf_init_listeners(waf_config_t *config);
void waf_close_listeners(waf_config_t *config);

#endif
