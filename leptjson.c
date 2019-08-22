#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL */

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)

typedef struct {
    const char *json;
} lept_context;

static void lept_parse_whitespace(lept_context *c)
{
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    c->json = p;
}

static int lept_parse_literal(lept_context *c, lept_value *v, const char *literal, lept_type type)
{
    size_t i;
    EXPECT(c, literal[0]);
    for(i = 0; literal[i + 1]; ++i) {
        if(c->json[i] != literal[i + 1]) {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_value(lept_context *c, lept_value *v)
{
    switch (*c->json) {
        case 'n':
            return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 't':
            return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f':
            return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case '\0':
            return LEPT_PARSE_EXPECT_VALUE;
        default:
            return LEPT_PARSE_INVALID_VALUE;
    }
}

int lept_parse(lept_value *v, const char *json)
{
    lept_context c;
    int result;  /* ISO C90 forbids mixed declarations and code */
    assert(v != NULL);
    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    result = lept_parse_value(&c, v);
    if (result == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*(c.json) != '\0') {
            result = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return result;
}

lept_type lept_get_type(const lept_value *v)
{
    assert(v != NULL);
    return v->type;
}
