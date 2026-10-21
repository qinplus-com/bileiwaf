#ifndef WAF_TRANSLATE_H
#define WAF_TRANSLATE_H

#include "waf.h"

#define MAX_TRANSLATE_LENGTH 10240

typedef enum {
    TRANSLATE_OK = 0,
    TRANSLATE_ERROR_SERVICE_UNAVAILABLE,
    TRANSLATE_ERROR_INVALID_API_KEY,
    TRANSLATE_ERROR_NETWORK,
    TRANSLATE_ERROR_UNSUPPORTED_LANGUAGE,
    TRANSLATE_ERROR_QUOTA_EXCEEDED,
    TRANSLATE_ERROR_UNKNOWN
} translate_error_t;

int translate_init(const char *api_key, translate_service_t service);
int translate_text(const char *text, const char *from_lang, const char *to_lang, 
                   char *result, size_t max_len);
int translate_html(const char *html, const char *from_lang, const char *to_lang,
                   char *result, size_t max_len);
void translate_cleanup(void);
const char* translate_error_str(translate_error_t error);

#endif