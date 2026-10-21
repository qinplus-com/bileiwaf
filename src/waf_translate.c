#include "../include/waf_translate.h"
#include "../include/waf_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <regex.h>

/* 翻译响应累积上限：防止异常/恶意响应导致内存无限扩张（8MiB 足够任何页面译文） */
#define TRANSLATE_RESP_MAX (8u * 1024u * 1024u)

/* 熔断冷却期：外部翻译 API 不可达时，冷却期内直接快速失败（零阻塞），
 * 避免每个请求都在数据面同步路径上白等数秒。 */
#define TRANSLATE_CIRCUIT_COOLDOWN_SEC 60

/* 记录熔断截止时间（unix 秒，0 表示正常）。跨线程用 GCC 原子内建访问。 */
static volatile long g_translate_down_until = 0;

static char api_key[256] = {0};
static translate_service_t current_service = TRANSLATE_GOOGLE;

/* curl_global_init 非线程安全，必须且只能在任何 curl_easy_* 调用前完成一次。
 * 历史缺陷：本模块曾用一个进程级 static CURL* 句柄供全部 64 个 worker 并发执行
 * curl_easy_setopt/curl_easy_perform（easy handle 不支持多线程共享），且 url_encode
 * 每次自行 easy_init/easy_cleanup 与惰性全局初始化竞争，2026-10-16 造成 libcurl 内部
 * 堆块跨线程释放，glibc 在 _int_free(curl_easy_setopt) 中检测到堆损坏并 abort。
 * 现在：全局初始化一次；每次请求使用独立 easy handle，用完即销毁。 */
static pthread_once_t g_curl_once = PTHREAD_ONCE_INIT;

static void global_curl_init(void) {
    curl_global_init(CURL_GLOBAL_ALL);
}

/* 翻译 HTTP 响应累积器（每个请求一个，栈上持有、堆上扩容，线程间完全隔离） */
typedef struct {
    char  *data;
    size_t len;
} resp_buf_t;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    resp_buf_t *buf = (resp_buf_t *)userdata;

    /* 超出上限直接丢弃后续数据（仍宣称已消费，避免 curl 报写错误），
     * 上层会因 JSON 解析失败而安全返回服务不可用。 */
    if (buf->len >= TRANSLATE_RESP_MAX) {
        return realsize;
    }
    size_t copy = realsize;
    if (buf->len + copy > TRANSLATE_RESP_MAX) {
        copy = TRANSLATE_RESP_MAX - buf->len;
    }

    char *tmp = realloc(buf->data, buf->len + copy + 1);
    if (!tmp) {
        /* 内存不足：丢弃本块，不破坏既有缓冲 */
        return realsize;
    }
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, copy);
    buf->len += copy;
    buf->data[buf->len] = '\0';
    return realsize;
}

/* 使用调用方提供的 easy handle 做 URL 编码，避免每次编码都 init/cleanup 句柄。
 * 返回 curl 分配、需由调用方 curl_free 的字符串。 */
static char *url_encode_with(CURL *curl, const char *str) {
    if (!curl || !str) return NULL;
    return curl_easy_escape(curl, str, 0);
}

int translate_init(const char *api_key_param, translate_service_t service) {
    pthread_once(&g_curl_once, global_curl_init);

    if (api_key_param && api_key_param[0]) {
        strncpy(api_key, api_key_param, sizeof(api_key) - 1);
        api_key[sizeof(api_key) - 1] = '\0';
    }
    current_service = service;
    return TRANSLATE_OK;
}

/* 在独立 easy handle 上执行一次 HTTP 翻译请求。
 * 成功返回 0 且 *out_response 为以 NUL 结尾、需 free 的响应体；失败返回非 0。 */
static int translate_http_get(const char *url, char **out_response) {
    *out_response = NULL;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return TRANSLATE_ERROR_NETWORK;
    }

    resp_buf_t buf = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    /* 数据面同步路径：超时压到最小，配合熔断把"不可达"的代价限制在单次 */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || !buf.data) {
        free(buf.data);
        return TRANSLATE_ERROR_NETWORK;
    }
    *out_response = buf.data;
    return TRANSLATE_OK;
}

int translate_google(const char *text, const char *from_lang, const char *to_lang,
                     char *result, size_t max_len) {
    if (!text || !to_lang) return TRANSLATE_ERROR_UNKNOWN;

    pthread_once(&g_curl_once, global_curl_init);
    CURL *curl = curl_easy_init();
    if (!curl) return TRANSLATE_ERROR_NETWORK;

    char *encoded_text = url_encode_with(curl, text);
    if (!encoded_text) {
        curl_easy_cleanup(curl);
        return TRANSLATE_ERROR_NETWORK;
    }

    char url[4096];
    snprintf(url, sizeof(url),
             "https://translate.googleapis.com/translate_a/single?"
             "client=gtx&sl=%s&tl=%s&dt=t&q=%s",
             from_lang ? from_lang : "auto", to_lang, encoded_text);
    curl_free(encoded_text);
    curl_easy_cleanup(curl);

    char *response = NULL;
    int http_ret = translate_http_get(url, &response);
    if (http_ret != TRANSLATE_OK) {
        return http_ret;
    }

    json_object *json_obj = json_tokener_parse(response);
    if (!json_obj) {
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *first_array = json_object_array_get_idx(json_obj, 0);
    if (!first_array) {
        json_object_put(json_obj);
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *second_array = json_object_array_get_idx(first_array, 0);
    if (!second_array) {
        json_object_put(json_obj);
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *translated_text = json_object_array_get_idx(second_array, 0);
    if (!translated_text) {
        json_object_put(json_obj);
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    const char *trans_str = json_object_get_string(translated_text);
    if (trans_str) {
        strncpy(result, trans_str, max_len - 1);
        result[max_len - 1] = '\0';
    }

    json_object_put(json_obj);
    free(response);
    return TRANSLATE_OK;
}

int translate_baidu(const char *text, const char *from_lang, const char *to_lang,
                    char *result, size_t max_len) {
    if (!text || !to_lang || !api_key[0]) return TRANSLATE_ERROR_UNKNOWN;

    pthread_once(&g_curl_once, global_curl_init);
    CURL *curl = curl_easy_init();
    if (!curl) return TRANSLATE_ERROR_NETWORK;

    char *encoded_text = url_encode_with(curl, text);
    if (!encoded_text) {
        curl_easy_cleanup(curl);
        return TRANSLATE_ERROR_NETWORK;
    }

    char url[4096];
    snprintf(url, sizeof(url),
             "https://fanyi-api.baidu.com/api/trans/vip/translate?"
             "q=%s&from=%s&to=%s&appid=%s&key=%s",
             encoded_text,
             from_lang ? from_lang : "auto",
             to_lang,
             api_key,
             api_key);
    curl_free(encoded_text);
    curl_easy_cleanup(curl);

    char *response = NULL;
    int http_ret = translate_http_get(url, &response);
    if (http_ret != TRANSLATE_OK) {
        return http_ret;
    }

    json_object *json_obj = json_tokener_parse(response);
    if (!json_obj) {
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *error_code_obj = json_object_object_get(json_obj, "error_code");
    if (error_code_obj) {
        int error_code = json_object_get_int(error_code_obj);
        json_object_put(json_obj);
        free(response);
        if (error_code == 52003) return TRANSLATE_ERROR_INVALID_API_KEY;
        if (error_code == 54004) return TRANSLATE_ERROR_QUOTA_EXCEEDED;
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *trans_result = json_object_object_get(json_obj, "trans_result");
    if (!trans_result) {
        json_object_put(json_obj);
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *first_result = json_object_array_get_idx(trans_result, 0);
    if (!first_result) {
        json_object_put(json_obj);
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    json_object *dst_obj = json_object_object_get(first_result, "dst");
    if (!dst_obj) {
        json_object_put(json_obj);
        free(response);
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    const char *trans_str = json_object_get_string(dst_obj);
    if (trans_str) {
        strncpy(result, trans_str, max_len - 1);
        result[max_len - 1] = '\0';
    }

    json_object_put(json_obj);
    free(response);
    return TRANSLATE_OK;
}

int translate_text(const char *text, const char *from_lang, const char *to_lang,
                   char *result, size_t max_len) {
    if (!text || !to_lang || max_len == 0) {
        return TRANSLATE_ERROR_UNKNOWN;
    }

    result[0] = '\0';

    pthread_once(&g_curl_once, global_curl_init);

    time_t now = time(NULL);

    /* 熔断开启：外部翻译 API 近期失败过，冷却期内直接快速失败，不占用 worker */
    if (__atomic_load_n(&g_translate_down_until, __ATOMIC_RELAXED) > (long)now) {
        return TRANSLATE_ERROR_SERVICE_UNAVAILABLE;
    }

    int rc;
    switch (current_service) {
        case TRANSLATE_GOOGLE:
            rc = translate_google(text, from_lang, to_lang, result, max_len);
            break;
        case TRANSLATE_BAIDU:
            rc = translate_baidu(text, from_lang, to_lang, result, max_len);
            break;
        default:
            rc = translate_google(text, from_lang, to_lang, result, max_len);
            break;
    }

    /* 网络不可达（含超时）判定为外部服务故障：开放熔断，避免每个请求重复白等。
     * 成功则清零，恢复翻译。 */
    if (rc == TRANSLATE_ERROR_NETWORK) {
        long prev = __atomic_exchange_n(&g_translate_down_until,
                                        (long)now + TRANSLATE_CIRCUIT_COOLDOWN_SEC,
                                        __ATOMIC_RELAXED);
        if (prev <= (long)now) {
            waf_log(LOG_LEVEL_WARN,
                    "Translation service unreachable, circuit opened for %ds",
                    TRANSLATE_CIRCUIT_COOLDOWN_SEC);
        }
    } else if (rc == TRANSLATE_OK) {
        __atomic_store_n(&g_translate_down_until, 0, __ATOMIC_RELAXED);
    }

    return rc;
}

int extract_text_from_html(const char *html, char *text, size_t max_len) {
    if (!html || !text || max_len == 0) return -1;

    text[0] = '\0';
    size_t text_len = 0;
    int in_tag = 0;
    int in_script = 0;
    int in_style = 0;

    for (const char *p = html; *p && text_len < max_len - 1; p++) {
        if (*p == '<') {
            in_tag = 1;
            continue;
        }

        if (*p == '>' && in_tag) {
            in_tag = 0;
            continue;
        }

        if (!in_tag) {
            text[text_len++] = *p;
        }
    }
    text[text_len] = '\0';
    return 0;
}

int translate_html(const char *html, const char *from_lang, const char *to_lang,
                   char *result, size_t max_len) {
    if (!html || !to_lang || max_len == 0) {
        return TRANSLATE_ERROR_UNKNOWN;
    }

    char extracted[4096] = {0};
    extract_text_from_html(html, extracted, sizeof(extracted));

    if (strlen(extracted) == 0) {
        strncpy(result, html, max_len - 1);
        result[max_len - 1] = '\0';
        return TRANSLATE_OK;
    }

    char translated[4096] = {0};
    int ret = translate_text(extracted, from_lang, to_lang, translated, sizeof(translated));

    if (ret != TRANSLATE_OK) {
        return ret;
    }

    strncpy(result, translated, max_len - 1);
    result[max_len - 1] = '\0';
    return TRANSLATE_OK;
}

void translate_cleanup(void) {
    /* 仅在进程退出时调用一次；此时所有 worker 均已停止。 */
    curl_global_cleanup();
}

const char* translate_error_str(translate_error_t error) {
    switch (error) {
        case TRANSLATE_OK:
            return "Success";
        case TRANSLATE_ERROR_SERVICE_UNAVAILABLE:
            return "Translation service unavailable";
        case TRANSLATE_ERROR_INVALID_API_KEY:
            return "Invalid API key";
        case TRANSLATE_ERROR_NETWORK:
            return "Network error";
        case TRANSLATE_ERROR_UNSUPPORTED_LANGUAGE:
            return "Unsupported language";
        case TRANSLATE_ERROR_QUOTA_EXCEEDED:
            return "Quota exceeded";
        case TRANSLATE_ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}
