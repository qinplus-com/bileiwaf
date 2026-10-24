#define _GNU_SOURCE
#include "../include/waf.h"
#include "../include/waf_log.h"
#include "../include/waf_http.h"
#include "../include/waf_rules.h"
#include "../include/waf_cc.h"
#include "../include/waf_ssl.h"
#include "../include/waf_translate.h"
#include "../include/waf_ai.h"
#include "../include/waf_ai_guard.h"
#include "../include/waf_captcha.h"
#include "../include/waf_blockpage.h"
// #include "../include/waf_api.h"
#include <signal.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <sys/ucontext.h>
#include <sys/syscall.h>
#include <unistd.h>

static waf_config_t global_config;
static ai_config_t ai_config;
static int running = 1;
/* SIGHUP 置位，由 403 渲染路径消费：拦截页配置含文件读取，不在信号处理器内做 */
static volatile sig_atomic_t g_blockpage_reload_pending = 0;
static time_t waf_start_time = 0;
static unsigned long request_count = 0;
static unsigned long attack_count = 0;
static unsigned long blocked_count = 0;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    int port;
    int is_https;
} connection_task_t;

/* worker 线程需在定义之前调用，前置声明消除隐式声明告警 */
int waf_process_connection(int client_fd, struct sockaddr_in *client_addr, int listen_port, int is_https);

typedef struct task_node {
    connection_task_t task;
    struct task_node *next;
} task_node_t;

static task_node_t *task_queue_head = NULL;
static task_node_t *task_queue_tail = NULL;
static pthread_mutex_t task_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t task_queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t *worker_threads = NULL;

/* 待处理连接上限：accept 速率远高于 worker 处理速率时，若无上限会让排队连接
 * 持续占用 fd，直至耗尽 65535 个描述符（历史事故根因）。超限直接丢弃新连接。 */
#define MAX_PENDING_TASKS 4096
static int pending_tasks = 0;
/* accept 错误日志限流时间戳 */
static time_t last_accept_err_log = 0;

static void *worker_thread_main(void *arg) {
    (void)arg;
    while (running) {
        pthread_mutex_lock(&task_queue_mutex);
        
        while (task_queue_head == NULL && running) {
            pthread_cond_wait(&task_queue_cond, &task_queue_mutex);
        }
        
        if (!running) {
            pthread_mutex_unlock(&task_queue_mutex);
            break;
        }
        
        task_node_t *node = task_queue_head;
        task_queue_head = task_queue_head->next;
        if (task_queue_head == NULL) {
            task_queue_tail = NULL;
        }
        if (pending_tasks > 0) pending_tasks--;
        
        pthread_mutex_unlock(&task_queue_mutex);
        
        connection_task_t task = node->task;
        free(node);
        
        waf_process_connection(task.client_fd, &task.client_addr, task.port, task.is_https);
    }
    
    return NULL;
}

static int enqueue_connection(int client_fd, struct sockaddr_in *client_addr, int port, int is_https) {
    task_node_t *node = malloc(sizeof(task_node_t));
    if (!node) {
        return -1;
    }
    
    node->task.client_fd = client_fd;
    node->task.client_addr = *client_addr;
    node->task.port = port;
    node->task.is_https = is_https;
    node->next = NULL;
    
    pthread_mutex_lock(&task_queue_mutex);

    if (pending_tasks >= MAX_PENDING_TASKS) {
        pthread_mutex_unlock(&task_queue_mutex);
        free(node);
        return -1;
    }
    pending_tasks++;

    if (task_queue_tail == NULL) {
        task_queue_head = node;
        task_queue_tail = node;
    } else {
        task_queue_tail->next = node;
        task_queue_tail = node;
    }
    
    pthread_cond_signal(&task_queue_cond);
    pthread_mutex_unlock(&task_queue_mutex);
    
    return 0;
}

static const char *waf_blocked_html = 
    "<!DOCTYPE html><html><head><title>403 Forbidden</title></head>"
    "<body><h1>403 Forbidden</h1><p>Access denied by Web Application Firewall.</p>"
    "<p>BileiWAF/1.0</p></body></html>";

static const char *waf_error_html = 
    "<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head>"
    "<body><h1>500 Internal Server Error</h1><p>Request processing failed.</p>"
    "</body></html>";

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        waf_log(LOG_LEVEL_INFO, "Received signal %d, shutting down...", sig);
        running = 0;
    } else if (sig == SIGHUP) {
        waf_log(LOG_LEVEL_INFO, "Received SIGHUP, scheduling rules/SSL reload...");
        /* 信号处理器内不做实际 reload（非 async-signal-safe）；仅置标志，
         * 由请求线程在 rules_check_request / 连接处理安全点执行 */
        rules_request_reload();
        waf_ssl_request_reload();   /* 证书续期后热加载 SSL 上下文 */
        g_blockpage_reload_pending = 1;  /* 403 拦截页/广告位配置热加载 */
    }
}

/* 崩溃处理器：把崩溃信号、故障指令地址与原始返回地址链写入 logs/waf-crash.log。
 *
 * 严格只允许 async-signal-safe 的调用。历史版本曾在处理器里调用
 * backtrace_symbols_fd()：它内部走 _dl_addr/PLT 惰性绑定，需要动态链接器加载锁与
 * malloc。2026-10-16 真实事故中，SIGABRT 由线程在持有 malloc arena 锁的 _int_free
 * 路径里触发，处理器内部又触发 calloc/PLT 绑定 → 永久自死锁，SA_RESETHAND 后也走
 * 不到重抛 → 进程"活着但全员挂起"，systemd Restart=on-failure 永远不生效。
 *
 * 现在：只记录原始地址（二进制带 -g/-rdynamic，事后用 addr2line 解析），并保证最终
 * 一定终止进程：恢复默认处置 + 解除阻塞 + tgkill 重抛；alarm(3) 兜底；_exit 终局。 */
static const char *crash_sig_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS:  return "SIGBUS";
        case SIGFPE:  return "SIGFPE";
        case SIGILL:  return "SIGILL";
        default:      return "SIG?";
    }
}

static void crash_write_u64_hex(int fd, unsigned long v) {
    char buf[19];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        int nib = (int)((v >> (60 - 4 * i)) & 0xf);
        buf[2 + i] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    buf[18] = '\n';
    /* 忽略写失败：崩溃路径无处可报 */
    ssize_t r = write(fd, buf, sizeof(buf));
    (void)r;
}

static void crash_handler(int sig, siginfo_t *info, void *uctx) {
    pid_t pid = getpid();
    long tid = syscall(SYS_gettid);

    int fd = open("logs/waf-crash.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        char hdr[192];
        int hl = snprintf(hdr, sizeof(hdr),
                          "\n===== CRASH sig=%d (%s) pid=%d tid=%ld time=%ld fault_addr=%p =====\n"
                          "fault_rip ",
                          sig, crash_sig_name(sig), pid, tid, (long)time(NULL),
                          info ? info->si_addr : NULL);
        if (hl > 0) {
            ssize_t r = write(fd, hdr, (size_t)hl);
            (void)r;
        }

        ucontext_t *uc = (ucontext_t *)uctx;
        unsigned long rip = 0, rbp = 0;
#ifdef REG_RIP
        rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
        rbp = (unsigned long)uc->uc_mcontext.gregs[REG_RBP];
#endif
        crash_write_u64_hex(fd, rip);

        /* 沿 RBP 帧链记录原始返回地址（最多 32 层）。地址明显非法即停止；
         * 若在遍历中二次访问错误内存，SA_RESETHAND 已恢复默认处置，会立即终止进程。 */
        const char *prefix = "frame ";
        for (int i = 0; i < 32 && rbp >= 0x10000UL && rbp < 0x7f0000000000UL
                         && (rbp & 0x7) == 0; i++) {
            unsigned long ret, next;
            /* 直接读栈帧；访问若再次缺页出错，SA_RESETHAND 已恢复默认处置，会立即终止进程 */
            ret  = *(unsigned long *)(rbp + 8);
            next = *(unsigned long *)(rbp);
            ssize_t r = write(fd, prefix, 6);
            (void)r;
            crash_write_u64_hex(fd, ret);
            if (next <= rbp) break; /* 帧链向高地址回溯，反向即链损坏 */
            rbp = next;
        }
        close(fd);
    }

    /* 确保进程真正死亡：恢复默认处置 → 解除阻塞 → tgkill 定向重抛给本线程，
     * 3 秒 alarm 兜底（SIGALRM 默认终止），最后 _exit 终局。 */
    struct sigaction dfl_act;
    memset(&dfl_act, 0, sizeof(dfl_act));
    dfl_act.sa_handler = SIG_DFL;
    sigemptyset(&dfl_act.sa_mask);
    sigaction(sig, &dfl_act, NULL);

    sigset_t unblock;
    sigemptyset(&unblock);
    sigaddset(&unblock, sig);
    pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);

    alarm(3);
    syscall(SYS_tgkill, (int)pid, (int)tid, sig);
    _exit(128 + sig);
}

/* 安装崩溃信号处理器（waf_start 中调用一次即可） */
static void install_crash_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);

    /* 预热处理器内会用到的 libc 包装函数的 PLT 绑定，避免崩溃信号打断别的线程正在
     * 进行的动态链接时，在信号处理器里再做惰性绑定而死锁在加载锁上。 */
    sigset_t warm;
    sigemptyset(&warm);
    pthread_sigmask(SIG_UNBLOCK, &warm, NULL);
    unsigned int left = alarm(0);
    (void)left;
    (void)syscall(SYS_gettid);
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_server_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to bind to port %d: %s", port, strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 1024) < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to listen on port %d: %s", port, strerror(errno));
        close(sock);
        return -1;
    }

    set_nonblocking(sock);

    waf_log(LOG_LEVEL_INFO, "WAF listening on port %d", port);

    return sock;
}

const char *get_content_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return "text/html";

    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcmp(ext, ".webp") == 0) return "image/webp";
    if (strcmp(ext, ".txt") == 0) return "text/plain";
    if (strcmp(ext, ".xml") == 0) return "application/xml";
    if (strcmp(ext, ".md") == 0) return "text/markdown";
    if (strcmp(ext, ".mp4") == 0) return "video/mp4";
    if (strcmp(ext, ".webm") == 0) return "video/webm";
    if (strcmp(ext, ".m3u8") == 0) return "application/vnd.apple.mpegurl";
    if (strcmp(ext, ".ts") == 0) return "video/mp2t";

    return "application/octet-stream";
}

/* 静态资源缓存策略：图片/视频内容稳定，给长缓存；HLS 清单可能更新，短缓存；
 * 其余（HTML/JS/CSS/JSON）返回 NULL，不加 Cache-Control，保持浏览器默认启发式缓存。 */
static const char *cache_policy_for(const char *path) {
    const char *e = strrchr(path, '.');
    if (!e) return NULL;
    if (!strcmp(e, ".png") || !strcmp(e, ".jpg") || !strcmp(e, ".jpeg") ||
        !strcmp(e, ".gif") || !strcmp(e, ".svg") || !strcmp(e, ".ico") ||
        !strcmp(e, ".webp"))
        return "public, max-age=604800";                  /* 图片：7 天 */
    if (!strcmp(e, ".mp4") || !strcmp(e, ".webm") || !strcmp(e, ".ts"))
        return "public, max-age=2592000, immutable";      /* 视频/切片：30 天 */
    if (!strcmp(e, ".m3u8"))
        return "public, max-age=60";                      /* HLS 清单：60 秒 */
    return NULL;
}

/* HTTP 日期（If-Modified-Since / Last-Modified）解析与格式化 */
static time_t http_parse_date(const char *s) {
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    if (!strptime(s, "%a, %d %b %Y %H:%M:%S GMT", &tmv)) return 0;
    return timegm(&tmv);
}

static void http_format_date(time_t t, char *out, size_t cap) {
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, cap, "%a, %d %b %Y %H:%M:%S GMT", &tmv);
}

/* 404 响应体：直接内嵌 WAF 产品页（web/index.html），并在 </body> 前注入弹窗提示。
 * 相对路径 web/index.html 基于 WAF_HOME（start.sh 以启动目录为 cwd）。
 * 读取失败时回退为极简 404 页。返回体长度写入 *out_len。 */
/* 404 弹窗：与 403 拦截页同一视觉（品牌 + 站点 + 状态标签 + 标语 + 双按钮），
 * 仅状态标签不同（404 / 403），便于用户区分是「页面不存在」还是「被安全策略拦截」。
 * 自包含内联样式，注入到 web/index.html 的 </body> 前。 */
static const char *waf_404_popup_html =
    "<div id=\"waf404mask\" style=\"position:fixed;inset:0;background:rgba(3,8,18,.72);"
    "backdrop-filter:blur(2px);z-index:99999;display:flex;align-items:center;justify-content:center;"
    "padding:20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif\">"
    "<div style=\"width:min(500px,92vw);padding:28px 26px;border:1px solid #1c2f4d;border-radius:16px;"
    "background:linear-gradient(160deg,#12233f,#0d1a2e);box-shadow:0 24px 64px rgba(0,0,0,.6);"
    "color:#d8e4f5;font-size:14px;line-height:1.75\">"
    "<div style=\"color:#22d3ee;font-weight:700;letter-spacing:2px;font-size:13px\">BILEI WAF 提供技术支持</div>"
    "<div style=\"color:#7fa6d0;font-size:12px;margin-top:2px\">bileiwaf.com</div>"
    "<div style=\"margin-top:12px;font-size:14px;color:#c3d3e6\">您访问的页面没有找到</div>"
    "<div style=\"margin:14px 0 0;font-size:15px;font-weight:600;color:#d8e4f5\">网站安全防护，部署即生效</div>"
    "<div style=\"display:flex;gap:10px;margin-top:16px;flex-wrap:wrap\">"
    "<a href=\"https://bileiwaf.com\" rel=\"noopener\" style=\"flex:1;min-width:140px;text-align:center;"
    "padding:9px 14px;border-radius:9px;border:1px solid #22d3ee;background:#0f2b45;color:#9fe8f6;"
    "font-size:13px;text-decoration:none\">访问 bileiwaf.com</a>"
    "<button onclick=\"if(document.referrer&&history.length>1){history.back()}else{document.getElementById('waf404mask').remove()}\" style=\"flex:1;min-width:140px;"
    "padding:9px 14px;border-radius:9px;border:1px solid #294260;background:transparent;color:#9fb3ca;"
    "font-size:13px;cursor:pointer;font-family:inherit\">继续浏览</button>"
    "</div></div></div>";

static const char *waf_404_fallback_html =
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";

/* 用户自定义 404 页面路径（waf.conf: error_404_page），waf_init 时从配置拷贝 */
static char g_error_404_page[1024] = "";

static size_t build_not_found_body(char *out, size_t cap) {
    /* 优先级 1：用户自定义 404 页面（error_404_page 指向的文件整体作为响应体） */
    if (g_error_404_page[0]) {
        FILE *uf = fopen(g_error_404_page, "rb");
        if (uf) {
            size_t ul = fread(out, 1, cap - 1, uf);
            fclose(uf);
            if (ul > 0) { out[ul] = '\0'; return ul; }
        }
        waf_log(LOG_LEVEL_WARN, "自定义 404 页面不可用，回退默认页: %s", g_error_404_page);
    }
    /* 优先级 2：默认演示页 + 弹窗提示 */
    FILE *f = fopen("web/index.html", "rb");
    if (!f) {
        size_t fl = strlen(waf_404_fallback_html);
        if (fl >= cap) fl = cap - 1;
        memcpy(out, waf_404_fallback_html, fl);
        return fl;
    }
    size_t popup_len = strlen(waf_404_popup_html);
    /* 预留弹窗与 </body> 注入空间 */
    size_t max_demo = (cap > popup_len + 16) ? (cap - popup_len - 16) : 0;
    size_t demo_len = fread(out, 1, max_demo, f);
    fclose(f);
    if (demo_len == 0) {
        size_t fl = strlen(waf_404_fallback_html);
        if (fl >= cap) fl = cap - 1;
        memcpy(out, waf_404_fallback_html, fl);
        return fl;
    }
    out[demo_len] = '\0';
    /* 在 </body> 前注入弹窗；找不到则追加到尾部 */
    char *pos = strcasestr(out, "</body>");
    if (pos) {
        size_t head_len = (size_t)(pos - out);
        size_t tail_len = demo_len - head_len;
        memmove(out + head_len + popup_len, pos, tail_len);
        memcpy(out + head_len, waf_404_popup_html, popup_len);
        return head_len + popup_len + tail_len;
    }
    memcpy(out + demo_len, waf_404_popup_html, popup_len);
    return demo_len + popup_len;
}

/* ACME HTTP-01 挑战：Let's Encrypt 校验请求必须由 WAF 本机直接响应。
 * 反代站点的后端通常没有 challenge 文件，若转发到后端必然校验失败。
 * 优先读取 WAF 固定 webroot（web/acme，续期时 certbot -w 指向此处），
 * 兼容历史配置把挑战文件写入站点 document_root 的情况。 */
static void serve_acme_challenge(int client_fd, http_request_t *req, waf_site_config_t *site,
                                 SSL *ssl, int is_https, int keep_alive) {
    static const char prefix[] = "/.well-known/acme-challenge/";
    const char *token = req->path + sizeof(prefix) - 1;
    char file_path[4096];
    FILE *file = NULL;

    /* 挑战文件名仅允许安全字符，杜绝路径穿越 */
    if (token[0] && !strchr(token, '/') && !strstr(token, "..") &&
        strcmp(req->method, "GET") == 0) {
        snprintf(file_path, sizeof(file_path), "web/acme%s", req->path);
        file = fopen(file_path, "rb");
        if (!file && site && site->document_root[0]) {
            snprintf(file_path, sizeof(file_path), "%s%s", site->document_root, req->path);
            file = fopen(file_path, "rb");
        }
    }

    http_response_t resp = {0};
    if (file) {
        char body[8192];
        size_t n = fread(body, 1, sizeof(body) - 1, file);
        fclose(file);
        resp.status_code = 200;
        strcpy(resp.status_message, "OK");
        http_set_body(&resp, body, n);
    } else {
        resp.status_code = 404;
        strcpy(resp.status_message, "Not Found");
        http_set_body(&resp, "not found", 9);
    }
    http_set_connection_header(&resp, keep_alive);
    if (is_https) {
        char resp_buf[MAX_REQUEST_SIZE];
        int resp_len = http_build_response(&resp, resp_buf, sizeof(resp_buf));
        waf_ssl_send(ssl, resp_buf, resp_len);
    } else {
        http_send_response(client_fd, &resp);
    }
}

/* 统一写访问日志：反代与拦截请求此前不写 waf-access.log，导致管理后台
 * “请求总数”只覆盖本地静态请求，出现攻击数 > 请求数的口径倒挂。 */
static void waf_log_request(const char *ip, const char *method, const char *url,
                            int status, long bytes_sent) {
    access_log_entry_t al = {
        .timestamp = time(NULL),
        .status_code = status,
        .bytes_received = 0,
        .bytes_sent = bytes_sent,
        .response_time = 0
    };
    strncpy(al.ip, ip, MAX_IP_LENGTH - 1);
    strncpy(al.method, method, sizeof(al.method) - 1);
    strncpy(al.url, url, MAX_URL_LENGTH - 1);
    log_write_access(&al);
}

/* 构造 403 拦截响应。浏览器类客户端返回可配置拦截页（可挂广告位，站长收益），
 * 显式只要 JSON/XML/纯文本的 API 客户端返回紧凑 JSON——广告页只应出现在
 * 人工可感知的浏览场景，不能污染接口语义。 */
static void fill_blocked_response(http_response_t *resp, http_request_t *req,
                                  const char *ip, const char *rule, int keep_alive) {
    resp->status_code = 403;
    snprintf(resp->status_message, sizeof(resp->status_message), "Forbidden");
    if (g_blockpage_reload_pending) {
        g_blockpage_reload_pending = 0;
        blockpage_reload();
    }
    http_set_header(resp, "X-Content-Type-Options", "nosniff");
    http_set_header(resp, "Cache-Control", "no-store");
    http_set_header(resp, "Referrer-Policy", "no-referrer");
    http_set_connection_header(resp, keep_alive);

    int want_html = 1;
    char *acc = (char *)http_get_header(req->headers, "Accept");
    if (acc) {
        if (!strstr(acc, "text/html") &&
            (strstr(acc, "application/json") || strstr(acc, "application/xml") ||
             strstr(acc, "text/plain")))
            want_html = 0;
        free(acc);
    }

    if (!want_html) {
        char safe[80];
        int n = 0;
        for (const char *p = rule ? rule : ""; *p && n < 64; p++)
            if (isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == '.')
                safe[n++] = *p;
        safe[n] = '\0';
        char body[256];
        int bl = snprintf(body, sizeof(body),
                          "{\"blocked\":true,\"by\":\"BileiWAF\",\"rule\":\"%s\"}", safe);
        http_set_header(resp, "Content-Type", "application/json; charset=UTF-8");
        http_set_body(resp, body, (size_t)bl);
        return;
    }

    /* 拦截页正文按请求渲染（含 IP/规则/URL），模板上限 32KB */
    char *buf = malloc(32768);
    if (buf) {
        char *ua = (char *)http_get_header(req->headers, "User-Agent");
        size_t n = blockpage_render(buf, 32768, ip, rule, req->url, ua);
        free(ua);
        if (n > 0) {
            http_set_header(resp, "Content-Type", "text/html; charset=UTF-8");
            http_set_body(resp, buf, n);
            free(buf);
            return;
        }
        free(buf);
    }
    http_set_header(resp, "Content-Type", "text/html; charset=UTF-8");
    http_set_body(resp, waf_blocked_html, strlen(waf_blocked_html));
}

int serve_static_file(int client_fd, http_request_t *req, waf_site_config_t *site, SSL *ssl, int is_https, int keep_alive) {
    const char *doc_root = (site && site->document_root[0]) ? site->document_root : "web";
    const char *path = req->path;
    char file_path[4096];
    /* 目录请求（含 "/"）映射到目录下 index.html，与 nginx 习惯一致 */
    if (path[strlen(path) - 1] == '/') {
        snprintf(file_path, sizeof(file_path), "%s%sindex.html", doc_root, path);
    } else {
        snprintf(file_path, sizeof(file_path), "%s%s", doc_root, path);
    }

    /* 路径穿越纵深防御：静态服务是纯静态站点（backend_port=0）的正式生产路径，
     * 不能只依赖规则层拦截 ../。realpath 解析后文件必须仍位于 document_root 之内，
     * 任何逃逸尝试（含符号链接指到站外）一律 403。 */
    char real_root[4096];
    char real_file[4096];
    int contained = 0;
    if (realpath(doc_root, real_root)) {
        if (realpath(file_path, real_file)) {
            size_t root_len = strlen(real_root);
            if (strncmp(real_file, real_root, root_len) == 0 &&
                (real_file[root_len] == '/' || real_file[root_len] == '\0')) {
                contained = 1;
            }
        }
    }
    if (!contained) {
        /* realpath 失败也可能只是文件不存在（404）；用词法检查区分穿越与普通缺失 */
        int traversal = (strstr(path, "/../") != NULL) ||
                        (strlen(path) >= 3 && strcmp(path + strlen(path) - 3, "/..") == 0) ||
                        (strstr(path, "%2e%2e") != NULL) || (strstr(path, "%2E%2E") != NULL);
        if (!traversal) {
            /* 落到原有 404 流程：用原路径 fopen（必然失败），复用下方统一 404 响应 */
        } else {
            waf_log(LOG_LEVEL_WARN, "Path traversal blocked: %s (docroot=%s)", path, doc_root);
            http_response_t deny_resp = {0};
            fill_blocked_response(&deny_resp, req, req->client_ip, "PATH-TRAVERSAL", keep_alive);
            if (is_https) {
                char resp_buf[MAX_REQUEST_SIZE];
                int resp_len = http_build_response(&deny_resp, resp_buf, sizeof(resp_buf));
                waf_ssl_send(ssl, resp_buf, resp_len);
            } else {
                http_send_response(client_fd, &deny_resp);
            }
            return -1;
        }
    }

    FILE *file = fopen(file_path, "rb");
    /* 演示入口共享路由：/demo、/screen、/report 等 WAF 演示页并不随业务站点
     * docroot 部署（docroot 是客户业务站点），未命中时统一回退到 WAF_HOME/web 下的
     * 演示页，确保 404 页上「攻防演示 / 大屏演示 / 测试报告」链接可用。 */
    if (!file) {
        const char *show = NULL;
        if (!strcmp(path, "/demo/"))                                            show = "web/demo/index.html";
        else if (!strcmp(path, "/demo") || !strcmp(path, "/demo.html"))         show = "web/demo.html";
        else if (!strcmp(path, "/screen") || !strcmp(path, "/screen.html"))     show = "web/screen.html";
        else if (!strcmp(path, "/report") || !strcmp(path, "/report.html"))     show = "web/report.html";
        if (show) {
            snprintf(file_path, sizeof(file_path), "%s", show);
            file = fopen(file_path, "rb");
        }
    }
    if (!file && (!strncmp(path, "/images/", 8) || !strncmp(path, "/assets/", 8) ||
                  !strncmp(path, "/docs/", 6) || !strncmp(path, "/demo/", 6))) {
        /* 站点 docroot 未命中共享静态资源（如 404 演示页引用的 logo）：
         * 回退到 WAF_HOME/web 下查找，避免 404 页出现裂图。
         * 文档页与只读演示目录同样走共享目录，便于多站点复用。 */
        snprintf(file_path, sizeof(file_path), "web%s", path);
        file = fopen(file_path, "rb");
    }
    if (!file) {
        waf_log(LOG_LEVEL_WARN, "Static file not found: %s", file_path);
        http_response_t error_resp = {
            .status_code = 404,
            .status_message = "Not Found"
        };
        /* 404 → 演示页面 + 弹窗提示（栈缓冲，http_set_body 内部拷贝） */
        char nf_body[MAX_BODY_SIZE];
        size_t nf_len = build_not_found_body(nf_body, sizeof(nf_body));
        http_set_body(&error_resp, nf_body, nf_len);
        http_set_connection_header(&error_resp, keep_alive);

        if (is_https) {
            char resp_buf[MAX_REQUEST_SIZE];
            int resp_len = http_build_response(&error_resp, resp_buf, sizeof(resp_buf));
            waf_ssl_send(ssl, resp_buf, resp_len);
        } else {
            http_send_response(client_fd, &error_resp);
        }

        access_log_entry_t access_log = {
            .timestamp = time(NULL),
            .status_code = 404,
            .bytes_received = 0,
            .bytes_sent = (long)nf_len,
            .response_time = 0
        };
        strncpy(access_log.ip, req->client_ip, MAX_IP_LENGTH - 1);
        strncpy(access_log.method, req->method, sizeof(access_log.method) - 1);
        strncpy(access_log.url, req->url, MAX_URL_LENGTH - 1);
        log_write_access(&access_log);

        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    const char *content_type = get_content_type(file_path);

    /* 缓存优化：图片/视频长缓存 + Last-Modified 条件请求（304） */
    const char *cache_policy = cache_policy_for(file_path);
    struct stat fst;
    time_t mtime = (fstat(fileno(file), &fst) == 0) ? fst.st_mtime : 0;
    char lastmod[64] = "";
    if (mtime > 0) http_format_date(mtime, lastmod, sizeof(lastmod));

    if (mtime > 0) {
        const char *ims = http_get_header(req->headers, "If-Modified-Since");
        if (ims) {
            time_t ims_t = http_parse_date(ims);
            free((void *)ims);
            if (ims_t > 0 && mtime <= ims_t) {
                fclose(file);
                char cc_line[96] = "";
                if (cache_policy)
                    snprintf(cc_line, sizeof(cc_line), "Cache-Control: %s\r\n", cache_policy);
                char h304[640];
                int l304 = snprintf(h304, sizeof(h304),
                    "HTTP/1.1 304 Not Modified\r\n"
                    "Last-Modified: %s\r\n"
                    "%s"
                    "Connection: %s\r\n"
                    "\r\n",
                    lastmod, cc_line,
                    keep_alive ? "keep-alive" : "close");
                if (is_https && ssl) {
                    waf_ssl_send(ssl, h304, l304);
                } else {
                    write(client_fd, h304, l304);
                }
                access_log_entry_t access_log = {
                    .timestamp = time(NULL),
                    .status_code = 304,
                    .bytes_received = 0,
                    .bytes_sent = 0,
                    .response_time = 0
                };
                strncpy(access_log.ip, req->client_ip, MAX_IP_LENGTH - 1);
                strncpy(access_log.method, req->method, sizeof(access_log.method) - 1);
                strncpy(access_log.url, req->url, MAX_URL_LENGTH - 1);
                log_write_access(&access_log);
                return 0;
            }
        }
    }

    char header_buf[768];
    char cc_line[96] = "", lm_line[96] = "";
    if (cache_policy)
        snprintf(cc_line, sizeof(cc_line), "Cache-Control: %s\r\n", cache_policy);
    if (lastmod[0])
        snprintf(lm_line, sizeof(lm_line), "Last-Modified: %s\r\n", lastmod);
    int header_len = snprintf(header_buf, sizeof(header_buf),
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: %ld\r\n"
        "Content-Type: %s\r\n"
        "%s%s"
        "Connection: %s\r\n"
        "%s"
        "\r\n", file_size, content_type, lm_line, cc_line,
        keep_alive ? "keep-alive" : "close",
        keep_alive ? "Keep-Alive: timeout=75, max=1000\r\n" : "");
    
    if (is_https && ssl) {
        waf_ssl_send(ssl, header_buf, header_len);
        
        char buffer[8192];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            waf_ssl_send(ssl, buffer, (int)bytes_read);
        }
    } else {
        write(client_fd, header_buf, header_len);
        
        char buffer[8192];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            write(client_fd, buffer, bytes_read);
        }
    }
    
    fclose(file);
    
    access_log_entry_t access_log = {
        .timestamp = time(NULL),
        .status_code = 200,
        .bytes_received = 0,
        .bytes_sent = file_size + header_len,
        .response_time = 0
    };
    strncpy(access_log.ip, req->client_ip, MAX_IP_LENGTH - 1);
    strncpy(access_log.method, req->method, sizeof(access_log.method) - 1);
    strncpy(access_log.url, req->url, MAX_URL_LENGTH - 1);
    log_write_access(&access_log);
    
    return 0;
}

int serve_static_file_old(int client_fd, http_request_t *req, waf_site_config_t *site, SSL *ssl, int is_https) {
    const char *doc_root = (site && site->document_root[0]) ? site->document_root : "web";
    const char *path = req->path;
    
    char file_path[4096];
    if (strcmp(path, "/") == 0) {
        snprintf(file_path, sizeof(file_path), "%s/index.html", doc_root);
    } else {
        snprintf(file_path, sizeof(file_path), "%s%s", doc_root, path);
    }
    
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        waf_log(LOG_LEVEL_WARN, "Static file not found: %s", file_path);
        http_response_t error_resp = {
            .status_code = 404,
            .status_message = "Not Found"
        };
        /* 404 → 演示页面 + 弹窗提示（栈缓冲，http_set_body 内部拷贝） */
        char nf_body[MAX_BODY_SIZE];
        size_t nf_len = build_not_found_body(nf_body, sizeof(nf_body));
        http_set_body(&error_resp, nf_body, nf_len);

        if (is_https) {
            char resp_buf[MAX_REQUEST_SIZE];
            int resp_len = http_build_response(&error_resp, resp_buf, sizeof(resp_buf));
            waf_ssl_send(ssl, resp_buf, resp_len);
        } else {
            http_send_response(client_fd, &error_resp);
        }
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *file_content = (char *)malloc((size_t)file_size);
    if (!file_content) {
        fclose(file);
        return -1;
    }
    
    fread(file_content, 1, (size_t)file_size, file);
    fclose(file);
    
    http_response_t response = {
        .status_code = 200,
        .status_message = "OK"
    };
    http_set_body(&response, file_content, (size_t)file_size);
    
    if (is_https) {
        char resp_buf[MAX_REQUEST_SIZE];
        int resp_len = http_build_response(&response, resp_buf, sizeof(resp_buf));
        waf_ssl_send(ssl, resp_buf, resp_len);
    } else {
        http_send_response(client_fd, &response);
    }
    
    free(file_content);
    return 0;
}

/* 代理发送：处理部分写，SSL/明文统一入口。
 * 注意 client_fd 是非阻塞 socket：send 遇 EAGAIN 时必须等待可写再重试，
 * 否则慢客户端会让响应被截断（连接被提前关闭）。 */
static int proxy_send_all(int fd, SSL *ssl, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (ssl) {
            ssize_t s = (ssize_t)waf_ssl_send(ssl, buf + off, (int)(len - off));
            if (s <= 0) return -1;
            off += (size_t)s;
            continue;
        }
        ssize_t s = send(fd, buf + off, len - off, 0);
        if (s < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fd_set wf;
                FD_ZERO(&wf);
                FD_SET(fd, &wf);
                struct timeval tv = {5, 0};
                if (select(fd + 1, NULL, &wf, NULL, &tv) <= 0) return -1;
                continue;
            }
            return -1;
        }
        if (s == 0) continue;
        off += (size_t)s;
    }
    return 0;
}

/* 过滤后端响应头中的 Connection/Keep-Alive 行，并按 keep_alive 追加正确的
 * Connection 头（keep-alive 时附带 Keep-Alive 参数）。
 * hdr_len 含结尾 \r\n\r\n。返回 out 中响应头总长度（含 \r\n\r\n），失败返回 0。 */
static size_t response_filter_connection(const char *hdr, size_t hdr_len,
                                         int keep_alive, char *out, size_t outsz) {
    size_t off = 0, pos = 0;
    size_t block_end = hdr_len >= 4 ? hdr_len - 4 : hdr_len;
    while (pos < block_end && off + 4 < outsz) {
        const char *eol = memmem(hdr + pos, block_end - pos, "\r\n", 2);
        size_t line_len = eol ? (size_t)(eol - (hdr + pos)) : block_end - pos;
        if (strncasecmp(hdr + pos, "Connection:", 11) != 0 &&
            strncasecmp(hdr + pos, "Keep-Alive:", 11) != 0) {
            if (off + line_len + 2 >= outsz) return 0;
            memcpy(out + off, hdr + pos, line_len);
            off += line_len;
            out[off++] = '\r'; out[off++] = '\n';
        }
        pos += eol ? line_len + 2 : line_len;
        if (!eol) break;
    }
    if (keep_alive) {
        off += snprintf(out + off, outsz - off,
                        "Connection: keep-alive\r\nKeep-Alive: timeout=75, max=1000\r\n");
    } else {
        off += snprintf(out + off, outsz - off, "Connection: close\r\n");
    }
    if (off + 2 > outsz) return 0;
    out[off++] = '\r'; out[off++] = '\n';
    return off;
}

/* 后端故障时给客户端返回网关错误（502/504），避免客户端收到空响应即可靠判定 */
static void proxy_send_gateway_error(int client_fd, SSL *ssl, int keep_alive,
                                     int status, const char *status_msg) {
    char body[256];
    int blen = snprintf(body, sizeof(body),
        "<!DOCTYPE html><html><head><title>%d %s</title></head>"
        "<body><h1>%d %s</h1><p>Upstream backend error.</p></body></html>",
        status, status_msg, status, status_msg);
    char resp[512];
    int rlen = snprintf(resp, sizeof(resp),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n\r\n",
        status, status_msg, blen, keep_alive ? "keep-alive" : "close");
    proxy_send_all(client_fd, ssl, resp, (size_t)rlen);
    proxy_send_all(client_fd, ssl, body, (size_t)blen);
}

int forward_to_backend(http_request_t *req, waf_site_config_t *site) {
    int backend_port = 0;
    if (site && site->enabled) {
        backend_port = site->backend_port;
    } else {
        backend_port = global_config.backend_port;
    }
    
    if (backend_port <= 0) {
        waf_log(LOG_LEVEL_DEBUG, "No backend configured, will serve static files");
        return -1;
    }
    
    int backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (backend_fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create backend socket");
        return -1;
    }

    /* 后端 I/O 超时（秒）：后端卡住/半开时不能让 worker 无限阻塞，
     * 否则 worker 会被逐个占满，最终全站不可用（历史事故根因）。
     * SO_SNDTIMEO 同样作用于阻塞式 connect()，故连接建立也有超时。 */
    struct timeval backend_tv = {10, 0};
    setsockopt(backend_fd, SOL_SOCKET, SO_SNDTIMEO, &backend_tv, sizeof(backend_tv));
    setsockopt(backend_fd, SOL_SOCKET, SO_RCVTIMEO, &backend_tv, sizeof(backend_tv));
    int nodelay = 1;
    setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    struct sockaddr_in backend_addr;
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;

    if (site && site->enabled) {
        backend_addr.sin_port = htons((uint16_t)site->backend_port);
        inet_pton(AF_INET, site->backend_host, &backend_addr.sin_addr);
    } else {
        backend_addr.sin_port = htons((uint16_t)global_config.backend_port);
        inet_pton(AF_INET, global_config.backend_host, &backend_addr.sin_addr);
    }

    if (connect(backend_fd, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) {
        /* 后端宕机时逐请求 ERROR 会刷爆错误日志（生产实测 6.5MB），节流为每 60s 一条 */
        static volatile time_t last_backend_err_log = 0;
        time_t now_s = time(NULL);
        time_t prev = __atomic_load_n(&last_backend_err_log, __ATOMIC_RELAXED);
        if (prev == 0 || now_s - prev >= 60) {
            __atomic_store_n(&last_backend_err_log, now_s, __ATOMIC_RELAXED);
            waf_log(LOG_LEVEL_ERROR, "Failed to connect to backend %s:%d (throttled, 1/min)",
                    site && site->enabled ? site->backend_host : global_config.backend_host,
                    site && site->enabled ? site->backend_port : global_config.backend_port);
        }
        close(backend_fd);
        return -1;
    }

    char buffer[MAX_REQUEST_SIZE];
    int len = http_build_request(req, buffer, sizeof(buffer));

    if (len > 0) {
        /* 强制后端短连接：响应边界由 Content-Length/EOF 决定，简化代理实现。
         * "keep-alive"(10字符) 原地替换为 "close"+5空格（头字段值允许拖尾 OWS）。 */
        char *conn = strcasestr(buffer, "\r\nConnection:");
        if (conn) {
            char *val = conn + 13;  /* 跳过 \r\nConnection: */
            while (*val == ' ') val++;
            if (strncasecmp(val, "keep-alive", 10) == 0) {
                memcpy(val, "close     ", 10);
            }
        }
        /* 完整写出请求：send 可能部分写入，未写完会让后端一直等剩余数据而卡死 */
        size_t off = 0;
        int send_ok = 1;
        while (off < (size_t)len) {
            ssize_t s = send(backend_fd, buffer + off, (size_t)len - off, 0);
            if (s < 0) {
                if (errno == EINTR) continue;
                send_ok = 0;
                break;
            }
            off += (size_t)s;
        }
        if (!send_ok) {
            waf_log(LOG_LEVEL_ERROR, "Failed to send request to backend");
            close(backend_fd);
            return -2;   /* 与 -1(未配置后端) 区分：后端已连通但写失败 */
        }
    }

    return backend_fd;
}

int waf_process_connection(int client_fd, struct sockaddr_in *client_addr, int listen_port, int is_https) {
    char client_ip[MAX_IP_LENGTH];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));

    waf_log(LOG_LEVEL_DEBUG, "Processing connection from %s:%d (port %d, %s)", 
           client_ip, ntohs(client_addr->sin_port), listen_port, is_https ? "HTTPS" : "HTTP");

    /* SIGHUP 安全点：若收到证书热加载请求，先重建 SSL 上下文再握手（新连接即用新证书） */
    waf_ssl_try_pending_reload(&global_config);

    SSL *ssl = NULL;
    if (is_https) {
        ssl = waf_ssl_accept(client_fd);
        if (!ssl) {
            close(client_fd);
            return -1;
        }
    }

    /* Keep-Alive 主循环：一个连接处理多个请求，直到客户端关闭、超时或
     * 请求 Connection: close。这是 HTTPS 性能的关键优化——避免每次请求
     * 都做完整 TLS 握手。 */
    char buffer[MAX_REQUEST_SIZE];
    size_t leftover = 0;
    int ka_timeout = global_config.keepalive_timeout > 0 ? global_config.keepalive_timeout : 75;
    int total_requests = 0;
    const int max_keepalive_requests = 1000;
    int received = 0;
    char leftover_first = 0;   /* 被 buffer[received]='\0' 覆盖的 leftover 首字节备份 */

    while (total_requests < max_keepalive_requests) {
        /* leftover 归位：http_receive_keepalive_request 不再前移流水线数据
         * （保护当前请求内容），约定由调用方在下次调用前把上次的流水线
         * 数据（buffer[received..received+leftover)）挪回 buffer 开头。
         * 挪前恢复上次被 NUL 覆盖的 leftover 首字节。 */
        if (leftover > 0 && total_requests > 0) {
            buffer[received] = leftover_first;
            memmove(buffer, buffer + received, leftover);
        }
        received = http_receive_keepalive_request(client_fd, buffer, sizeof(buffer),
                                                  &leftover, ka_timeout, ssl);
        if (received <= 0) {
            break;  /* 连接关闭或 keep-alive 超时 */
        }
        if (leftover > 0) {
            leftover_first = buffer[received];
        }
        buffer[received] = '\0';
        total_requests++;

        http_request_t request;
        if (http_parse_request(buffer, (size_t)received, &request) < 0) {
            waf_log(LOG_LEVEL_WARN, "Failed to parse HTTP request from %s", client_ip);
            http_response_t error_resp = {
                .status_code = 400,
                .status_message = "Bad Request"
            };
            http_set_body(&error_resp, "Invalid HTTP request", 20);
            http_set_connection_header(&error_resp, 0);
            if (is_https) {
                char resp_buf[MAX_REQUEST_SIZE];
                int resp_len = http_build_response(&error_resp, resp_buf, sizeof(resp_buf));
                waf_ssl_send(ssl, resp_buf, resp_len);
            } else {
                http_send_response(client_fd, &error_resp);
            }
            break;  /* 解析失败，关闭连接 */
        }

        strncpy(request.client_ip, client_ip, MAX_IP_LENGTH - 1);
        request.client_port = ntohs(client_addr->sin_port);
        int keep_alive = http_should_keep_alive(&request);

        waf_log(LOG_LEVEL_DEBUG, "%s %s %s (ka=%d)", client_ip, request.method, request.url, keep_alive);

        waf_site_config_t *site = NULL;
        char host_header[256];
        if (http_get_header_value(request.headers, "Host", host_header, sizeof(host_header)) >= 0) {
            site = waf_find_site(&global_config, host_header);
        }

        /* ACME HTTP-01 挑战：由本机直接响应，不进入规则/CC 检测，也不转发后端 */
        if (strncmp(request.path, "/.well-known/acme-challenge/", 28) == 0) {
            serve_acme_challenge(client_fd, &request, site, ssl, is_https, keep_alive);
            if (!keep_alive) break;
            continue;
        }

        /* waf.dbask.cn 管理后台：直接返回静态文件 */
        if (site && strcmp(site->domains[0], "waf.dbask.cn") == 0) {
            serve_static_file(client_fd, &request, site, ssl, is_https, keep_alive);
            if (!keep_alive) break;
            continue;
        }

        /* CC 人机验证端点（站点开 cc_captcha 时）：在 CC/规则检测之前处理，
         * 否则已触发 CC 的 IP 会被拦截而永远拿不到验证页。
         * 403 页「继续浏览」也复用该端点，因此 blockpage 开启 verify 时同样放通。 */
        if (captcha_is_endpoint(request.url) &&
            ((site && site->cc_captcha) || blockpage_verify_enabled())) {
            if (captcha_handle(client_fd, &request, ssl, is_https, keep_alive)) {
                if (!keep_alive) break;
                continue;
            }
        }

        attack_match_t match = {0};
        int attack_detected = 0;

        if (access_check_ip(client_ip) == WAF_ACTION_BLOCK) {
            attack_detected = 1;
            match.type = ATTACK_UNKNOWN;
            match.severity = 10;
            strcpy(match.rule_id, "IP-BLACKLIST");
            strcpy(match.description, "IP Blacklisted");
        }

        /* 规则/AI 检测优先于 CC 验证码挑战：恶意请求即使触发 CC 也应被规则拦截（403），
         * 避免被 302 验证码吞掉导致测试工具误判为放行、检出率虚低。 */
        if (!attack_detected) {
            if (rules_check_request(&request, &match)) {
                attack_detected = 1;
                waf_log(LOG_LEVEL_WARN, "Attack detected: %s from %s - %s",
                       match.description, client_ip, request.url);
            }
        }

        /* CC 防护：仅对未命中攻击规则的请求生效。已封禁态(ccr==1)直接拦截；
         * 刚超阈值(ccr==2)按站点配置分流（验证码挑战 或 直接封禁）。 */
        if (!attack_detected && global_config.enable_cc_protection) {
            /* 0=放行 1=封禁态 2=刚超阈值（不自动封禁，按站点开关分流） */
            int ccr = cc_check_request(client_ip, &request);
            if (ccr == 2) {
                if (site && site->cc_captcha &&
                    captcha_check_clearance(client_ip, request.headers)) {
                    /* 已验证真人且放行 cookie 有效：重置计数放行 */
                    cc_reset_ip(client_ip);
                } else if (site && site->cc_captcha) {
                    /* 302 → /waf-captcha?to=<原URL>，不写攻击日志 */
                    waf_log(LOG_LEVEL_INFO, "CC challenge issued to %s for %s",
                            client_ip, request.url);
                    captcha_send_challenge(client_fd, &request, ssl, is_https, keep_alive);
                    if (!keep_alive) break;
                    continue;
                } else {
                    /* 站点未开验证：保持原封禁语义 */
                    cc_block_ip(client_ip, cc_block_duration());
                    attack_detected = 1;
                    match.type = ATTACK_CC;
                    match.severity = 8;
                    strcpy(match.rule_id, "CC-LIMIT");
                    strcpy(match.description, "Rate Limit Exceeded");
                }
            } else if (ccr == 1) {
                attack_detected = 1;
                match.type = ATTACK_CC;
                match.severity = 8;
                strcpy(match.rule_id, "CC-LIMIT");
                strcpy(match.description, "Rate Limit Exceeded");
            }
        }

        /* AI 影子模式 */
        if (ai_config.enabled) {
            int ai_conf = ai_guard_shadow(&ai_config, &request, attack_detected);
            /* 双通道融合就绪时，拦截决策已由 rules_check_request 的 auto 级联
             * 完成（AI-DETECT）；此处旧 LR 内联拦截仅在融合未就绪的纯 LR 遗留
             * 模式下启用。ensemble_threshold<=0 视为无效阈值不启用（否则 cutoff=0
             * 会把 ai_conf>=0 的全部请求误拦——v1.2.0 生产事故根因） */
            if (!ai_config.fusion_ready && !ai_config.shadow_mode && !attack_detected &&
                ai_config.ensemble_threshold > 0.0 &&
                ai_conf >= (int)(ai_config.ensemble_threshold * 100.0 + 0.5)) {
                attack_detected = 1;
                match.type = ATTACK_UNKNOWN;
                match.severity = 5;
                strcpy(match.rule_id, "AI-DETECT");
                strcpy(match.description, "AI detected malicious request");
            }
        }

        /* 403 页「继续浏览（需验证）」：已验证真人持有效放行 cookie 时放行本次请求，
         * 否则验证完仍会被同一条规则拦截。黑名单 IP 不参与放行（人工封禁优先）。 */
        int bp_verified = 0;
        if (attack_detected && blockpage_verify_enabled() &&
            strcmp(match.rule_id, "IP-BLACKLIST") != 0 &&
            captcha_check_clearance(client_ip, request.headers)) {
            bp_verified = 1;
            waf_log(LOG_LEVEL_INFO, "blockpage: verified pass ip=%s rule=%s url=%s",
                    client_ip, match.rule_id, request.url);
        }

        if (attack_detected) {
            attack_log_entry_t log_entry = {0};
            log_entry.timestamp = time(NULL);
            log_entry.type = match.type;
            log_entry.severity = match.severity;
            log_entry.action = (global_config.mode == WAF_MODE_BLOCKING && !bp_verified)
                               ? WAF_ACTION_BLOCK : WAF_ACTION_LOG;
            strncpy(log_entry.ip, client_ip, MAX_IP_LENGTH - 1);
            strncpy(log_entry.url, request.url, MAX_URL_LENGTH - 1);
            strncpy(log_entry.path, request.path, MAX_URL_LENGTH - 1);
            strncpy(log_entry.query, request.query, MAX_URL_LENGTH - 1);
            strncpy(log_entry.method, request.method, sizeof(log_entry.method) - 1);
            strncpy(log_entry.attack_pattern, match.pattern, sizeof(log_entry.attack_pattern) - 1);
            strncpy(log_entry.matched_content, match.matched_content, sizeof(log_entry.matched_content) - 1);
            strncpy(log_entry.description, match.description, sizeof(log_entry.description) - 1);
            strncpy(log_entry.rule_id, match.rule_id, sizeof(log_entry.rule_id) - 1);
            char *ua = (char *)http_get_header(request.headers, "User-Agent");
            if (ua) { strncpy(log_entry.user_agent, ua, sizeof(log_entry.user_agent) - 1); free(ua); }
            char *referer = (char *)http_get_header(request.headers, "Referer");
            if (referer) { strncpy(log_entry.referer, referer, sizeof(log_entry.referer) - 1); free(referer); }
            if (request.body_len > 0)
                strncpy(log_entry.request_body, request.body, sizeof(log_entry.request_body) - 1);
            log_write_attack(&log_entry);

            if (global_config.mode == WAF_MODE_BLOCKING && !bp_verified) {
                http_response_t blocked_resp = {0};
                fill_blocked_response(&blocked_resp, &request, client_ip,
                                      match.rule_id[0] ? match.rule_id : "UNKNOWN", keep_alive);
                if (is_https) {
                    char resp_buf[MAX_REQUEST_SIZE];
                    int resp_len = http_build_response(&blocked_resp, resp_buf, sizeof(resp_buf));
                    waf_ssl_send(ssl, resp_buf, resp_len);
                } else {
                    http_send_response(client_fd, &blocked_resp);
                }
                waf_log_request(client_ip, request.method, request.url, 403,
                                (long)blocked_resp.body_len);
                if (!keep_alive) break;
                continue;
            }
        }

        if (global_config.mode == WAF_MODE_LEARNING) {
            http_response_t learning_resp = { .status_code = 200, .status_message = "OK" };
            char info[1024];
            snprintf(info, sizeof(info), "WAF Learning Mode - Request Allowed\nIP: %s\nURL: %s\n",
                    client_ip, request.url);
            http_set_body(&learning_resp, info, strlen(info));
            http_set_connection_header(&learning_resp, keep_alive);
            if (is_https) {
                char resp_buf[MAX_REQUEST_SIZE];
                int resp_len = http_build_response(&learning_resp, resp_buf, sizeof(resp_buf));
                waf_ssl_send(ssl, resp_buf, resp_len);
            } else {
                http_send_response(client_fd, &learning_resp);
            }
            if (!keep_alive) break;
            continue;
        }

        /* 转发到后端 */
        int backend_fd = forward_to_backend(&request, site);
        if (backend_fd == -2) {
            /* 后端已连通但请求写失败：返回 502，不让客户端挂起 */
            proxy_send_gateway_error(client_fd, ssl, keep_alive, 502, "Bad Gateway");
            waf_log_request(client_ip, request.method, request.url, 502, 0);
            if (!keep_alive) break;
            continue;
        }
        if (backend_fd < 0) {
            serve_static_file(client_fd, &request, site, ssl, is_https, keep_alive);
            if (!keep_alive) break;
            continue;
        }

        /* 代理后端响应。后端请求已强制 Connection: close（forward_to_backend），
         * 响应边界由 Content-Length 或 EOF 决定：
         * - 有 Content-Length：按长度精确转发，客户端连接按 keep_alive 复用；
         * - 无 Content-Length（chunked/旧式）：流转到 EOF 后关闭客户端连接。 */
        char hdr_buf[16384];
        size_t hdr_total = 0, header_end = 0;
        int backend_broken = 0;
        while (hdr_total < sizeof(hdr_buf) - 1) {
            ssize_t n = recv(backend_fd, hdr_buf + hdr_total, sizeof(hdr_buf) - 1 - hdr_total, 0);
            if (n < 0) { if (errno == EINTR) continue; backend_broken = 1; break; }
            if (n == 0) { backend_broken = 1; break; }  /* 无完整响应头即 EOF */
            hdr_total += (size_t)n;
            hdr_buf[hdr_total] = '\0';
            char *he = strstr(hdr_buf, "\r\n\r\n");
            if (he) { header_end = (size_t)(he - hdr_buf) + 4; break; }
        }

        if (backend_broken || header_end == 0) {
            /* 后端未返回合法响应：
             * - 已读到部分原始数据：尽量转发后关闭（无法在前面插入新的状态行）；
             * - 完全没读到（含后端读超时）：返回 504，让客户端快速得到明确结果。 */
            if (hdr_total > 0) {
                proxy_send_all(client_fd, ssl, hdr_buf, hdr_total);
                waf_log_request(client_ip, request.method, request.url, 502, (long)hdr_total);
            } else {
                proxy_send_gateway_error(client_fd, ssl, 0, 504, "Gateway Timeout");
                waf_log_request(client_ip, request.method, request.url, 504, 0);
            }
            close(backend_fd);
            break;
        }

        /* 从状态行解析响应码，供访问日志使用 */
        int resp_status = 0;
        sscanf(hdr_buf, "HTTP/%*d.%*d %d", &resp_status);

        /* 翻译（保持原行为：仅翻译首个缓冲区，命中后发送译文并关闭连接） */
        if (site && site->translate_enabled && site->target_lang_count > 0) {
            char accept_language[256];
            int use_translated = 0;
            char translated_buffer[MAX_REQUEST_SIZE] = {0};
            if (http_get_header_value(request.headers, "Accept-Language", accept_language, sizeof(accept_language)) >= 0) {
                char *lang_start = accept_language;
                while (*lang_start) {
                    char *lang_end = strchr(lang_start, ',');
                    if (lang_end) *lang_end = '\0';
                    char *q_start = strchr(lang_start, ';');
                    if (q_start) *q_start = '\0';
                    for (int i = 0; i < site->target_lang_count; i++) {
                        if (strncmp(lang_start, site->target_languages[i], strlen(site->target_languages[i])) == 0) {
                            translate_init(site->translate_api_key, site->translate_service);
                            int ret = translate_html(hdr_buf, site->language, site->target_languages[i],
                                                     translated_buffer, sizeof(translated_buffer));
                            if (ret == TRANSLATE_OK && strlen(translated_buffer) > 0) {
                                use_translated = 1;
                            }
                            break;
                        }
                    }
                    if (use_translated) break;
                    if (!lang_end) break;
                    lang_start = lang_end + 1;
                }
            }
            if (use_translated) {
                proxy_send_all(client_fd, ssl, translated_buffer, strlen(translated_buffer));
                waf_log_request(client_ip, request.method, request.url,
                                resp_status > 0 ? resp_status : 200, (long)strlen(translated_buffer));
                close(backend_fd);
                break;
            }
        }

        /* 解析 Content-Length（仅限响应头范围内） */
        long content_length = -1;
        char *cl = strcasestr(hdr_buf, "Content-Length:");
        if (cl && (size_t)(cl - hdr_buf) < header_end) {
            content_length = strtol(cl + 15, NULL, 10);
            if (content_length < 0) content_length = -1;
        }

        int proxy_keep = keep_alive && content_length >= 0;

        /* 重写响应头：剥离后端 Connection/Keep-Alive，按 proxy_keep 设置 */
        char out_hdr[17408];
        size_t out_len = response_filter_connection(hdr_buf, header_end, proxy_keep,
                                                    out_hdr, sizeof(out_hdr));
        if (out_len == 0 || proxy_send_all(client_fd, ssl, out_hdr, out_len) < 0) {
            close(backend_fd);
            break;
        }

        /* 转发已随响应头读入的 body 部分 */
        size_t body_in_buf = hdr_total - header_end;
        if (content_length >= 0 && body_in_buf > (size_t)content_length) {
            body_in_buf = (size_t)content_length;
        }
        if (body_in_buf > 0 &&
            proxy_send_all(client_fd, ssl, hdr_buf + header_end, body_in_buf) < 0) {
            close(backend_fd);
            break;
        }
        long resp_bytes = (long)out_len + (long)body_in_buf;

        if (content_length >= 0) {
            /* 按剩余长度精确转发 body */
            long remaining = content_length - (long)body_in_buf;
            while (remaining > 0) {
                size_t want = (size_t)remaining < sizeof(hdr_buf) ? (size_t)remaining : sizeof(hdr_buf);
                ssize_t n = recv(backend_fd, hdr_buf, want, 0);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) { remaining = -1; break; }
                if (proxy_send_all(client_fd, ssl, hdr_buf, (size_t)n) < 0) { remaining = -1; break; }
                resp_bytes += n;
                remaining -= n;
            }
            if (remaining != 0) { close(backend_fd); break; }  /* 转发不完整，关连接 */
        } else {
            /* 无 Content-Length：流转到 EOF */
            ssize_t n;
            while ((n = recv(backend_fd, hdr_buf, sizeof(hdr_buf), 0)) > 0) {
                if (proxy_send_all(client_fd, ssl, hdr_buf, (size_t)n) < 0) break;
                resp_bytes += n;
            }
        }
        close(backend_fd);
        waf_log_request(client_ip, request.method, request.url,
                        resp_status > 0 ? resp_status : 200, resp_bytes);

        if (!proxy_keep) break;
        continue;
    }

    if (ssl) waf_ssl_shutdown(ssl);
    close(client_fd);
    return 0;
}

int waf_init(waf_config_t *config) {
    if (!config) {
        memset(&global_config, 0, sizeof(global_config));
        global_config.http_port = WAF_DEFAULT_HTTP_PORT;
        global_config.https_port = WAF_DEFAULT_HTTPS_PORT;
        global_config.worker_threads = WAF_WORKER_THREADS;
        global_config.mode = WAF_MODE_BLOCKING;
        global_config.enable_cc_protection = 1;
        global_config.enable_api_protection = 1;
        global_config.ssl_enabled = 0;
        global_config.max_body_size = MAX_BODY_SIZE;
        strcpy(global_config.backend_host, WAF_DEFAULT_BACKEND_HOST);
        global_config.backend_port = WAF_DEFAULT_BACKEND_PORT;
        strcpy(global_config.log_dir, "logs");
        strcpy(global_config.rules_dir, "rules");
        global_config.log_rotate_size_mb = WAF_DEFAULT_LOG_ROTATE_MB;
        global_config.log_retention_days = WAF_DEFAULT_LOG_RETENTION;
    } else {
        memcpy(&global_config, config, sizeof(global_config));
    }
    /* 自定义 404 页面路径（waf.conf: error_404_page），供 build_not_found_body 使用 */
    snprintf(g_error_404_page, sizeof(g_error_404_page), "%s", global_config.error_404_page);

    log_init(global_config.log_dir);
    /* 日志轮转与保留期策略（waf.conf: log_rotate_size / log_retention_days） */
    log_set_rotation(global_config.log_rotate_size_mb, global_config.log_retention_days);
    waf_log(LOG_LEVEL_INFO, "WAF v%s initializing...", WAF_VERSION);

    rules_init(global_config.rules_dir, &global_config);
    ai_init(&ai_config, &global_config);
    rules_set_ai_config(&ai_config);
    /* 启动护栏后台铸造线程（在独立线程做铸规则/白样本评估，不占用请求线程） */
    ai_guard_init(&ai_config);

    cc_config_t cc_config = {
        .enabled = global_config.enable_cc_protection,
        .max_requests = 100,
        .time_window = 60,
        .action = WAF_ACTION_BLOCK,
        .block_duration = 300,
        .auto_blacklist_enabled = global_config.auto_blacklist_enabled,
        .auto_blacklist_seconds = global_config.auto_blacklist_seconds
    };
    cc_init(&cc_config);
    captcha_init();
    /* 403 拦截页（config/blockpage.conf）：自定义模板 + 广告位，失败自动回退极简页 */
    blockpage_init();

    waf_sites_init(&global_config);

    /* 配置查找顺序：CWD 相对路径 → $WAF_HOME → configure 安装前缀 → 历史路径 /opt/waf */
    const char *site_config_paths[4] = {
        "config/sites.conf",
        NULL,   /* filled below: $WAF_HOME/config/sites.conf */
        WAF_PREFIX "/config/sites.conf",
        "/opt/waf/config/sites.conf"
    };
    static char waf_home_sites_path[512];
    {
        const char *home = getenv("WAF_HOME");
        if (home && home[0]) {
            snprintf(waf_home_sites_path, sizeof(waf_home_sites_path),
                     "%s/config/sites.conf", home);
            site_config_paths[1] = waf_home_sites_path;
        }
    }

    for (int i = 0; i < (int)(sizeof(site_config_paths)/sizeof(site_config_paths[0])); i++) {
        if (!site_config_paths[i]) continue;
        if (waf_load_sites_from_file(&global_config, site_config_paths[i]) == 0) {
            waf_log(LOG_LEVEL_INFO, "Loaded site config from: %s", site_config_paths[i]);
            break;
        }
    }

    if (global_config.site_count == 0) {
        waf_log(LOG_LEVEL_INFO, "Adding default site...");
        /* Default site follows the configured default backend (-b) */
        waf_add_site(&global_config, "waf.demo.local", "",
                     config->backend_host, config->backend_port);
    }

    if (!global_config.ssl_enabled && global_config.site_count > 0) {
        for (int i = 0; i < global_config.site_count; i++) {
            waf_site_config_t *site = &global_config.sites[i];
            if (site->cert_file[0] && site->key_file[0]) {
                global_config.ssl_enabled = 1;
                strncpy(global_config.cert_file, site->cert_file, sizeof(global_config.cert_file) - 1);
                strncpy(global_config.key_file, site->key_file, sizeof(global_config.key_file) - 1);
                break;
            }
        }
    }

    waf_init_listeners(&global_config);
    waf_print_sites(&global_config);

    if (global_config.ssl_enabled && global_config.cert_file[0] && global_config.key_file[0]) {
        if (waf_ssl_init(&global_config) == 0) {
            waf_log(LOG_LEVEL_INFO, "HTTPS enabled on port %d", global_config.https_port);
        } else {
            waf_log(LOG_LEVEL_WARN, "Failed to initialize SSL, HTTPS will be disabled");
            global_config.ssl_enabled = 0;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    waf_log(LOG_LEVEL_INFO, "WAF initialization complete");
    waf_log(LOG_LEVEL_INFO, "  - Mode: %s", 
           global_config.mode == WAF_MODE_LEARNING ? "Learning" :
           global_config.mode == WAF_MODE_DETECTION ? "Detection" : "Blocking");
    waf_log(LOG_LEVEL_INFO, "  - Default Backend: %s:%d", 
           global_config.backend_host, global_config.backend_port);
    waf_log(LOG_LEVEL_INFO, "  - HTTP Port: %d", global_config.http_port);
    waf_log(LOG_LEVEL_INFO, "  - HTTPS Port: %d%s", 
           global_config.https_port, 
           global_config.ssl_enabled ? " (enabled)" : " (disabled)");

    return 0;
}

int waf_start(void) {
    waf_log(LOG_LEVEL_INFO, "Starting WAF...");
    waf_start_time = time(NULL);
    install_crash_handlers();

    int max_fd = -1;
    for (int i = 0; i < global_config.listener_count; i++) {
        int sock = create_server_socket(global_config.listeners[i].port);
        if (sock < 0) {
            continue;
        }
        global_config.listeners[i].fd = sock;
        if (sock > max_fd) {
            max_fd = sock;
        }
    }

    if (max_fd < 0) {
        waf_log(LOG_LEVEL_ERROR, "Failed to create any listening sockets");
        return -1;
    }

    // int api_fd = api_init();
    // if (api_fd >= 0) {
    //     if (api_fd > max_fd) {
    //         max_fd = api_fd;
    //     }
    // }

    int num_threads = global_config.worker_threads;
    if (num_threads <= 0) {
        num_threads = 4;
    }
    
    worker_threads = malloc(sizeof(pthread_t) * num_threads);
    if (!worker_threads) {
        waf_log(LOG_LEVEL_ERROR, "Failed to allocate worker threads");
        return -1;
    }
    
    waf_log(LOG_LEVEL_INFO, "Starting %d worker threads...", num_threads);
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&worker_threads[i], NULL, worker_thread_main, NULL) != 0) {
            waf_log(LOG_LEVEL_ERROR, "Failed to create worker thread %d", i);
            running = 0;
            pthread_cond_broadcast(&task_queue_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(worker_threads[j], NULL);
            }
            free(worker_threads);
            worker_threads = NULL;
            return -1;
        }
    }

    waf_log(LOG_LEVEL_INFO, "WAF started with %d worker threads", num_threads);

    /* 使用 epoll 替代 select：O(1) 事件通知，无 FD_SETSIZE(1024) 限制，
     * 支持高并发连接接入。 */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        waf_log(LOG_LEVEL_ERROR, "epoll_create1 failed: %s", strerror(errno));
        return -1;
    }
    struct epoll_event ev;
    for (int i = 0; i < global_config.listener_count; i++) {
        if (global_config.listeners[i].fd >= 0) {
            ev.events = EPOLLIN;
            ev.data.fd = global_config.listeners[i].fd;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, global_config.listeners[i].fd, &ev) < 0) {
                waf_log(LOG_LEVEL_ERROR, "epoll_ctl add listener %d failed: %s",
                       global_config.listeners[i].fd, strerror(errno));
            }
        }
    }

    struct epoll_event events[64];
    while (running) {
        int n = epoll_wait(epfd, events, 64, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            waf_log(LOG_LEVEL_ERROR, "epoll_wait failed: %s", strerror(errno));
            break;
        }
        if (n == 0) {
            static time_t last_cleanup = 0;
            time_t now = time(NULL);
            if (now - last_cleanup > 300) {
                cc_cleanup_old_records();
                captcha_cleanup();
                last_cleanup = now;
            }
            continue;
        }

        for (int i = 0; i < n; i++) {
            for (int j = 0; j < global_config.listener_count; j++) {
                waf_listener_t *listener = &global_config.listeners[j];
                if (listener->fd >= 0 && events[i].data.fd == listener->fd) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd = accept(listener->fd, (struct sockaddr*)&client_addr, &client_len);
                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                        /* fd 耗尽(EMFILE/ENFILE)或监听 fd 异常(ENOTSOCK)时，pending 连接仍
                         * 留在队列中使 epoll 持续就绪，若直接 continue 会以外呼数十万次/秒的
                         * 速度空转刷日志（历史事故中约 5 分钟写出 9GB 错误日志）。此处退避
                         * 50ms 并把日志限流为每 10s 一条。 */
                        if (errno == EMFILE || errno == ENFILE || errno == ENOTSOCK) {
                            struct timespec ts = {0, 50 * 1000 * 1000};
                            nanosleep(&ts, NULL);
                            time_t now = time(NULL);
                            if (now - last_accept_err_log >= 10) {
                                last_accept_err_log = now;
                                waf_log(LOG_LEVEL_ERROR, "Accept failed on port %d: %s (throttled)",
                                       listener->port, strerror(errno));
                            }
                            continue;
                        }
                        waf_log(LOG_LEVEL_ERROR, "Accept failed on port %d: %s",
                               listener->port, strerror(errno));
                        continue;
                    }
                    set_nonblocking(client_fd);
                    if (enqueue_connection(client_fd, &client_addr, listener->port, listener->is_https) != 0) {
                        /* 待处理队列已满或内存不足：直接丢弃，避免继续吃 fd 导致全站不可用 */
                        close(client_fd);
                    }
                }
            }
        }
    }

    close(epfd);

    pthread_cond_broadcast(&task_queue_cond);
    
    if (worker_threads) {
        int num_threads = global_config.worker_threads > 0 ? global_config.worker_threads : 4;
        for (int i = 0; i < num_threads; i++) {
            pthread_join(worker_threads[i], NULL);
        }
        free(worker_threads);
        worker_threads = NULL;
    }

    waf_close_listeners(&global_config);
    waf_ssl_cleanup();

    waf_log(LOG_LEVEL_INFO, "WAF stopped");

    return 0;
}

void waf_stop(void) {
    running = 0;
}

waf_config_t* waf_get_config(void) {
    return &global_config;
}

int waf_process_request(waf_context_t *ctx) {
    if (!ctx) return -1;

    return rules_check_request(&ctx->request, &ctx->result.match);
}

int waf_init_listeners(waf_config_t *config) {
    if (!config) return -1;
    
    config->listener_count = 0;
    
    if (config->http_port > 0) {
        config->listeners[config->listener_count].port = config->http_port;
        config->listeners[config->listener_count].is_https = 0;
        config->listener_count++;
    }
    
    if (config->https_port > 0 && config->ssl_enabled && 
        config->cert_file[0] && config->key_file[0]) {
        config->listeners[config->listener_count].port = config->https_port;
        config->listeners[config->listener_count].is_https = 1;
        config->listener_count++;
    }
    
    waf_log(LOG_LEVEL_INFO, "Initialized %d listeners", config->listener_count);
    return 0;
}

void waf_close_listeners(waf_config_t *config) {
    if (!config) return;
    
    for (int i = 0; i < config->listener_count; i++) {
        if (config->listeners[i].fd > 0) {
            close(config->listeners[i].fd);
            config->listeners[i].fd = -1;
        }
    }
    config->listener_count = 0;
}