#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <errno.h> /* errno, ERANGE */
#include <math.h> /* HUGE_VAL */
#include <string.h>  /* memcpy() */
#include <stdio.h>  /* sprintf() */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
    #define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
    #define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len)     memcpy(lept_context_push(c, len), s, len)

#define LIKELY(x) __builtin_expect(!!(x), 1) /* x is very likely to be true */
#define UNLIKELY(x) __builtin_expect(!!(x), 0) /* x is very likely to be false */

#define RAISE_STRING_ERROR(error) do { c->top = head; return error;} while(0)

typedef struct {
    const char *json;
    char *stack;
    size_t size, top;
} lept_context;

static void *lept_context_push(lept_context *c, size_t size)
{
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size) {
            c->size += c->size >> 1;    /* c->size * 1.5 */
        }
        c->stack = (char *)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *c, size_t size)
{
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

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
    } else { /* Nonzero should start with 1-9 */
        if(!(ISDIGIT1TO9(*end))) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        for(++end; ISDIGIT(*end); ++end); /* followed by 0 or more digits */
    }
    if(*end == '.') {   /* handle decimal */
        ++end;
        if(!ISDIGIT(*end)) { /* the decimal part must have at least one digit */
            return LEPT_PARSE_INVALID_VALUE;
        }
        for(++end; ISDIGIT(*end); ++end);   /* skip these decimal digits */
    }
    if(*end == 'e' || *end == 'E') { /* handle exponent */
        ++end;
        if(*end == '+' || *end == '-') { /* for exponent, both + and - are legal */
            ++end;
        }
        if(!ISDIGIT(*end)) { /* must have one or more digits */
            return LEPT_PARSE_INVALID_VALUE;
        }
        for(++end; ISDIGIT(*end); ++end); /* skip these digits */
    }
    errno = 0; /* set it to zero before conversion */
    v->u.n = strtod(c->json, NULL);
    if(errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) { /* overflow */
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    c->json = end;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static const char *lept_parse_hex4(const char *p, unsigned *u)
{
    unsigned i, temp;
    for(i = 0, *u = 0; i != 4; ++i, ++p) {
        if(ISDIGIT(*p)) {
            temp = (*p) - '0';
        } else if('a' <= (*p) && (*p) <= 'f') {
            temp = (*p) - 'a' + 10;
        } else if('A' <= (*p) && (*p) <= 'F') {
            temp = (*p) - 'A' + 10;
        } else {
            return NULL;
        }
        *u = (*u << 4) | temp;
    }
    return p;
}

static void lept_encode_utf8(lept_context *c, unsigned u)
{
    assert(u <= 0x10FFFF); /* unicode character: U+0000 ~ U+10FFFF */
    if(u <= 0x007F) {
        PUTC(c, u);
    } else if(u <= 0x07FF) {
        PUTC(c, 0xC0 | (u >> 6));
        PUTC(c, 0x80 | (u & 0x3F));
    } else if(u <= 0xFFFF) {
        PUTC(c, 0xE0 | (u >> 12));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    } else {
        PUTC(c, 0xF0 | (u >> 18));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >> 6) & 0x3F));
        PUTC(c, 0x80 | (u & 0x3F));
    }
}

static int lept_parse_string_raw(lept_context *c, const char **str, size_t *len)
{
    size_t head = c->top;
    unsigned u, low;
    const char *p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = (const char *)lept_context_pop(c, *len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                RAISE_STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            case '\\':
                switch (*p++) {
                    case '"':
                        PUTC(c, '"');
                        break;
                    case '\\':
                        PUTC(c, '\\');
                        break;
                    case '/':
                        PUTC(c, '/');
                        break;
                    case 'b':
                        PUTC(c, '\b');
                        break;
                    case 'f':
                        PUTC(c, '\f');
                        break;
                    case 'n':
                        PUTC(c, '\n');
                        break;
                    case 'r':
                        PUTC(c, '\r');
                        break;
                    case 't':
                        PUTC(c, '\t');
                        break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u))) {
                            RAISE_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        }
                        if(0xD800 <= u && u <= 0xDBFF) { /* surrogate pair */
                            if(!(*p++ == '\\' && *p++ == 'u')) {
                                RAISE_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                            if(!(p = lept_parse_hex4(p, &low))) {
                                RAISE_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            }
                            if(!(0xDC00 <= low && low <= 0xDFFF)) {
                                RAISE_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                            u = 0x10000 + (u - 0xD800) * 0x400 + (low - 0xDC00);
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        RAISE_STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            default:
                /* handle invalid characters */
                if(UNLIKELY((unsigned char)ch < 0x20)) {
                    c->top = head;
                    return LEPT_PARSE_INVALID_STRING_CHAR;
                }
                PUTC(c, ch);
        }
    }
}

static int lept_parse_string(lept_context *c, lept_value *v)
{
    int ret;
    const char *s;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK) {
        lept_set_string(v, s, len);
    }
    return ret;
}

/* forward declaration for mutual recursion */
static int lept_parse_value(lept_context *c, lept_value *v);

static int lept_parse_array(lept_context *c, lept_value *v)
{
    size_t size = 0, i;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') { /* empty array */
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            break;
        }
        lept_parse_whitespace(c);
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        if (*c->json == ',') {
            c->json++;
        } else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value); /* the actual size of elements in memory */
            memcpy(v->u.a.e = (lept_value *)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* free memory to avoid leaks */
    for (i = 0; i != size; ++i) {
        lept_free((lept_value *)lept_context_pop(c, sizeof(lept_value)));
    }
    return ret;
}

static int lept_parse_object(lept_context *c, lept_value *v)
{
    size_t size = 0, i;
    lept_member m;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {  /* empty object */
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.m = NULL;
        v->u.o.size = 0;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    for (;;) {
        const char *key;
        lept_init(&m.v);
        /* parse key */
        lept_parse_whitespace(c);
        if((*c->json != '\"') || (ret = lept_parse_string_raw(c, &key, &m.klen)) != LEPT_PARSE_OK) {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        memcpy(m.k = (char *)malloc(m.klen + 1), key, m.klen);
        m.k[m.klen] = '\0';    /* don't forget! */
        /* parse colon */
        lept_parse_whitespace(c);
        if(*(c->json)++ != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        /* parse value */
        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }
        /* copy current lept_member */
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse comma or right-curly-brace */
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
        } else if (*c->json == '}') {
            c->json++;
            v->type = LEPT_OBJECT;
            v->u.o.size = size;
            size *= sizeof(lept_member);
            memcpy(v->u.o.m = (lept_member *)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    free(m.k); /* if the last member hasn't been pushed into stack yet */
    /* pop and free members on the stack */
    for(i = 0; i != size; ++i) {
        lept_member *m = (lept_member *)lept_context_pop(c, sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    return ret;
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
        case '\"':
            return lept_parse_string(c, v);
        case '[':
            return lept_parse_array(c, v);
        case '{':
            return lept_parse_object(c, v);
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
    c.stack = NULL;
    c.top = c.size = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    result = lept_parse_value(&c, v);
    if (result == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*(c.json) != '\0') {
            result = LEPT_PARSE_ROOT_NOT_SINGULAR;
            v->type = LEPT_NULL;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return result;
}

void lept_free(lept_value *v)
{
    assert(v != NULL);
    switch(v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY: {
            size_t i;
            for(i = 0; i != v->u.a.size; ++i) {
                lept_free(v->u.a.e + i);
            }
            free(v->u.a.e);
            break;
        }
        case LEPT_OBJECT: {
            size_t i;
            for(i = 0; i != v->u.o.size; ++i) {
                free((v->u.o.m + i)->k);
                lept_free(&(v->u.o.m + i)->v);
            }
            free(v->u.o.m);
            break;
        }
        default:    /* add default to suppress warnings about non-exhaustive matching */
            break;
    }
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value *v)
{
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value *v, double n)
{
    lept_free(v);
    v->type = LEPT_NUMBER;
    v->u.n = n;
}

const char *lept_get_string(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

void lept_set_string(lept_value *v, const char *s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char *)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

int lept_get_boolean(const lept_value *v)
{
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value *v, int b)
{
    lept_free(v);
    v->type = (b ? LEPT_TRUE : LEPT_FALSE);
}

size_t lept_get_array_size(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

size_t lept_get_array_capacity(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.capacity;
}

lept_value *lept_get_array_element(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(0 <= index && index < v->u.a.size);
    return v->u.a.e + index;
}

void lept_set_array(lept_value *v, size_t capacity)
{
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_ARRAY;
    v->u.a.size = 0;
    v->u.a.capacity = capacity;
    v->u.a.e = capacity > 0 ? (lept_value *)malloc(capacity * sizeof(lept_value)) : NULL;
}

void lept_reserve_array(lept_value *v, size_t capacity)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity < capacity) {
        v->u.a.capacity = capacity;
        v->u.a.e = (lept_value *)realloc(v->u.a.e, capacity * sizeof(lept_value));
    }
}

void lept_shrink_array(lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity > v->u.a.size) {
        v->u.a.capacity = v->u.a.size;
        v->u.a.e = (lept_value *)realloc(v->u.a.e, v->u.a.capacity * sizeof(lept_value));
    }
}

lept_value *lept_pushback_array_element(lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.size == v->u.a.capacity) {
        lept_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    }
    lept_init(&v->u.a.e[v->u.a.size]);
    return &v->u.a.e[v->u.a.size++];
}

void lept_popback_array_element(lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY && v->u.a.size > 0);
    lept_free(&v->u.a.e[--v->u.a.size]);
}

void lept_clear_array(lept_value *v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    while(v->u.a.size > 0) {
        lept_free(&v->u.a.e[--v->u.a.size]);
    }
}

lept_value *lept_insert_array_element(lept_value *v, size_t index)
{
    size_t i;
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(0 <= index && index <= v->u.a.size);   /* if index == size, then this's equivalent to pushback*/
    if (v->u.a.size == v->u.a.capacity) {
        lept_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    }
    for(i = v->u.a.size++; i != index; --i) {
        v->u.a.e[i] = v->u.a.e[i - 1];
    }
    return &v->u.a.e[index];
}

void lept_erase_array_element(lept_value *v, size_t index, size_t count)
{
    size_t i;
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(0 <= index && 0 <= count && index + count <= v->u.a.size);
    if(!count) {
        return;
    }
    for(i = index; i != index + count; ++i) {
        lept_free(&v->u.a.e[i]);
        v->u.a.e[i] = v->u.a.e[i + count];
    }
    for(i = index + count; i != v->u.a.size; ++i) {
        v->u.a.e[i] = v->u.a.e[i + count];
    }
    v->u.a.size -= count;
}

size_t lept_get_object_size(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

size_t lept_get_object_capacity(const lept_value *v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.capacity;
}

const char *lept_get_object_key(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(0 <= index && index < v->u.o.size);
    return (v->u.o.m + index)->k;
}

size_t lept_get_object_key_length(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(0 <= index && index < v->u.o.size);
    return (v->u.o.m + index)->klen;
}

lept_value *lept_get_object_value(const lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(0 <= index && index < v->u.o.size);
    return &((v->u.o.m + index)->v);
}

size_t lept_find_object_index(const lept_value *v, const char *key, size_t klen)
{
    size_t i;
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (i = 0; i < v->u.o.size; i++)
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0) {
            return i;
        }
    return LEPT_KEY_NOT_EXIST;
}

lept_value *lept_find_object_value(const lept_value *v, const char *key, size_t klen)
{
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

void lept_set_object(lept_value *v, size_t capacity)
{
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_OBJECT;
    v->u.o.size = 0;
    v->u.o.capacity = capacity;
    v->u.o.m = capacity > 0 ? (lept_member *)malloc(capacity * sizeof(lept_member)) : NULL;
}

void lept_reserve_object(lept_value *v, size_t capacity)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity < capacity) {
        v->u.o.capacity = capacity;
        v->u.o.m = (lept_member *)realloc(v->u.o.m, capacity * sizeof(lept_member));
    }
}

void lept_shrink_object(lept_value *v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    if(v->u.o.size < v->u.o.capacity) {
        v->u.o.capacity = v->u.o.size;
        v->u.o.m = (lept_member *)realloc(v->u.o.m, v->u.o.size * sizeof(lept_member));
    }
}

void lept_clear_object(lept_value *v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    while(v->u.o.size > 0) {
        lept_member *m = &v->u.o.m[--v->u.o.size];
        free(m->k);
        lept_free(&m->v);
    }
}

lept_value *lept_set_object_value(lept_value *v, const char *key, size_t klen)
{
    size_t index = lept_find_object_index(v, key, klen);
    if(index != LEPT_KEY_NOT_EXIST) {   /* avoid adding duplicate keys */
        return &v->u.o.m[index].v;
    }
    if(v->u.o.size == v->u.o.capacity) {
        lept_reserve_object(v, v->u.o.capacity ? 2 * v->u.o.capacity : 1);
    }
    v->u.o.m[v->u.o.size].k = (char *)malloc((klen + 1) * sizeof(char));
    memcpy(v->u.o.m[v->u.o.size].k, key, klen);
    v->u.o.m[v->u.o.size].k[klen] = '\0';
    v->u.o.m[v->u.o.size].klen = klen;
    lept_init(&v->u.o.m[v->u.o.size].v);
    return &v->u.o.m[v->u.o.size++].v;
}

void lept_remove_object_value(lept_value *v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(0 <= index && index < v->u.o.size);
    free(v->u.o.m[index].k);
    lept_free(&v->u.o.m[index].v);
    while(index <= v->u.o.size - 2) {
        v->u.o.m[index] = v->u.o.m[index + 1];
        ++index;
    }
    --v->u.o.size;
}

static void lept_stringify_string(lept_context *c, const char *s, size_t len)
{
    size_t i;
    PUTC(c, '\"');
    for(i = 0; i != len; ++i) {
        const char ch = *(s + i);
        switch(ch) {
            case '"':
                PUTS(c, "\\\"", 2);
                break;
            case '\\':
                PUTS(c, "\\\\", 2);
                break;
            case '\b':
                PUTS(c, "\\b", 2);
                break;
            case '\f':
                PUTS(c, "\\f", 2);
                break;
            case '\n':
                PUTS(c, "\\n", 2);
                break;
            case '\r':
                PUTS(c, "\\r", 2);
                break;
            case '\t':
                PUTS(c, "\\t", 2);
                break;
            default:
                if(UNLIKELY((unsigned char)ch < 0x20)) {
                    sprintf(lept_context_push(c, 6), "\\u%04x", ch);
                } else {
                    PUTC(c, ch);
                }
        }
    }
    PUTC(c, '\"');
}

static void lept_stringify_value(lept_context *c, const lept_value *v)
{
    switch (v->type) {
        case LEPT_NULL:
            PUTS(c, "null",  4);
            break;
        case LEPT_FALSE:
            PUTS(c, "false", 5);
            break;
        case LEPT_TRUE:
            PUTS(c, "true",  4);
            break;
        case LEPT_NUMBER:
            c->top -= 32 - sprintf(lept_context_push(c, 32), "%.17g", v->u.n);
            break;
        case LEPT_STRING:
            lept_stringify_string(c, v->u.s.s, v->u.s.len);
            break;
        case LEPT_ARRAY: {
            size_t i;
            PUTC(c, '[');
            for(i = 0; i != v->u.a.size; ++i) {
                if(LIKELY(i != 0)) {
                    PUTC(c, ',');
                }
                lept_stringify_value(c, v->u.a.e + i);
            }
            PUTC(c, ']');
            break;
        }
        case LEPT_OBJECT: {
            size_t i;
            PUTC(c, '{');
            for(i = 0; i != v->u.o.size; ++i) {
                if(LIKELY(i != 0)) {
                    PUTC(c, ',');
                }
                lept_stringify_string(c, (v->u.o.m + i)->k, (v->u.o.m + i)->klen);
                PUTC(c, ':');
                lept_stringify_value(c, &((v->u.o.m + i)->v));
            }
            PUTC(c, '}');
            break;
        }
        default:
            assert(0 && "invalid type");
    }
}

char *lept_stringify(const lept_value *v, size_t *length)
{
    lept_context c;
    assert(v != NULL);
    c.stack = (char *)malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length) {
        *length = c.top;
    }
    PUTC(&c, '\0');
    return c.stack;
}

int lept_is_equal(const lept_value *lhs, const lept_value *rhs)
{
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type) {
        return 0;
    }
    switch (lhs->type) {
        case LEPT_STRING:
            return lhs->u.s.len == rhs->u.s.len &&
                   memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case LEPT_NUMBER:
            return lhs->u.n == rhs->u.n;
        case LEPT_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size) {
                return 0;
            }
            for (i = 0; i != lhs->u.a.size; ++i)
                if (!lept_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i])) {
                    return 0;
                }
            return 1;
        case LEPT_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size) {
                return 0;
            }
            for(i = 0; i != lhs->u.o.size; ++i) {
                lept_value *v = lept_find_object_value(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen);
                if(!v || !lept_is_equal(&lhs->u.o.m[i].v, v)) {
                    return 0;
                }
            }
            return 1;
        default:
            return 1;
    }
}

void lept_copy(lept_value *dst, const lept_value *src)
{
    size_t i;
    assert(src != NULL && dst != NULL && src != dst);
    switch (src->type) {
        case LEPT_STRING:
            lept_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case LEPT_ARRAY:
            lept_set_array(dst, src->u.a.size);
            for(i = 0; i != src->u.a.size; ++i) {
                lept_init(dst->u.a.e + i);
                lept_copy(dst->u.a.e + i, src->u.a.e + i);
            }
            dst->u.a.size = src->u.a.size;
            break;
        case LEPT_OBJECT:
            lept_set_object(dst, src->u.o.size);
            for(i = 0; i != src->u.o.size; ++i) {
                dst->u.o.m[i].klen = src->u.o.m[i].klen;
                dst->u.o.m[i].k = (char *)malloc(dst->u.o.m[i].klen + 1);
                memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, dst->u.o.m[i].klen);
                dst->u.o.m[i].k[dst->u.o.m[i].klen] = '\0';
                lept_init(&dst->u.o.m[i].v);
                lept_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            dst->u.o.size = src->u.o.size;
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value *dst, lept_value *src)
{
    assert(dst != NULL && src != NULL && src != dst);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value *lhs, lept_value *rhs)
{
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        lept_value temp;
        memcpy(&temp, lhs, sizeof(lept_value));
        memcpy(lhs,   rhs, sizeof(lept_value));
        memcpy(rhs, &temp, sizeof(lept_value));
    }
}
