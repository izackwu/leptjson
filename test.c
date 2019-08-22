#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "leptjson.h"

static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define EXPECT_EQ_BASE(equality, expect, actual, format) \
    do {\
        test_count++;\
        if (equality)\
            test_pass++;\
        else {\
            fprintf(stderr, "%s:%d: expect: " format " actual: " format "\n", __FILE__, __LINE__, expect, actual);\
            main_ret = 1;\
        }\
    } while(0)

#define EXPECT_EQ_INT(expect, actual) EXPECT_EQ_BASE((expect) == (actual), expect, actual, "%d")

#define TEST_LITERAL(expected_type, json)\
    do{\
        lept_value v;\
        v.type = (expected_type == LEPT_FALSE ? LEPT_TRUE: LEPT_FALSE);\
        EXPECT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, json));\
        EXPECT_EQ_INT(expected_type, lept_get_type(&v));\
    }while(0)

static void test_parse_null()
{
    TEST_LITERAL(LEPT_NULL, "null");
}

static void test_parse_true()
{
    TEST_LITERAL(LEPT_TRUE, "true");
}

static void test_parse_false()
{
    TEST_LITERAL(LEPT_FALSE, "false");
}


#define TEST_ERROR(error, json)\
    do {\
        lept_value v;\
        v.type = LEPT_FALSE;\
        EXPECT_EQ_INT(error, lept_parse(&v, json));\
        EXPECT_EQ_INT(LEPT_NULL, lept_get_type(&v));\
    } while(0)

static void test_parse_expect_value()
{
    TEST_ERROR(LEPT_PARSE_EXPECT_VALUE, "");
    TEST_ERROR(LEPT_PARSE_EXPECT_VALUE, " ");
}

static void test_parse_invalid_value()
{
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "nul");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "?");
}

static void test_parse_root_not_singular()
{
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "null x");
}

static void test_parse()
{
    test_parse_null();
    test_parse_false();
    test_parse_true();
    test_parse_expect_value();
    test_parse_invalid_value();
    test_parse_root_not_singular();
}

int main()
{
    test_parse();
    printf("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);
    return main_ret;
}
