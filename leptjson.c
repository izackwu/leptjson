#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL */

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')

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

static int lept_parse_number(lept_context *c, lept_value *v)
{
    const char *end;
    end = c->json;
    if(*end == '-') { /* Skip minus sign but not posivitve sign*/
        ++end;
    }
    if(*end == '0') { /* Zero must has only one digit */
        ++end;
        /* comment these because we should treat this error as LEPT_PARSE_ROOT_NOT_SINGULAR */
        #if 0
        if(*end == 'x' || *end == 'X'){ /* Binary floating-point expression is not allowed */
            return LEPT_PARSE_INVALID_VALUE;
        }
        #endif
    } else { /* Nonzero should start with 1-9 */
        if(!(ISDIGIT1TO9(*end))) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        for(++end; ISDIGIT(*end); ++end); /* followed by 0 or more digits */
    }
    if(*end == '.'){    /* handle decimal */
        ++end;
        if(!ISDIGIT(*end)){ /* the decimal part must have at least one digit */
            return LEPT_PARSE_INVALID_VALUE;
        }
        for(++end; ISDIGIT(*end); ++end);   /* skip these decimal digits */
    }
    if(*end == 'e' || *end == 'E'){ /* handle exponent */
        ++end;
        if(*end == '+' || *end == '-'){ /* for exponent, both + and - are legal */
            ++end;
        }
        if(!ISDIGIT(*end)){ /* must have one or more digits */
            return LEPT_PARSE_INVALID_VALUE;
        }
        for(++end; ISDIGIT(*end); ++end); /* skip these digits */
    }
    v->n = strtod(c->json, NULL);
    c->json = end;
    v->type = LEPT_NUMBER;
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
            return lept_parse_number(c, v);
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
            v->type = LEPT_NULL;
        }
    }
    return result;
}

lept_type lept_get_type(const lept_value *v)
{
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}
