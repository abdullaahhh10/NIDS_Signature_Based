import re

def convert_pcre_to_python(pcre_pattern):
    if not (pcre_pattern.startswith("/") and pcre_pattern.rfind("/") > 0):
        raise ValueError(f"Invalid PCRE pattern format: {pcre_pattern}")

    last_slash = pcre_pattern.rfind("/")
    pattern = pcre_pattern[1:last_slash]  
    modifiers = pcre_pattern[last_slash + 1:]

    flags = 0
    if "i" in modifiers: flags |= re.IGNORECASE
    if "m" in modifiers: flags |= re.MULTILINE
    if "s" in modifiers: flags |= re.DOTALL
    if "x" in modifiers: flags |= re.VERBOSE

    try:
        return re.compile(pattern, flags)
    
    except re.error as e:
        raise ValueError(f"Invalid converted regex: {pattern}. Error: {str(e)}")

def check_payload(payload, pcre_rule):
   
    try:
        regex = convert_pcre_to_python(pcre_rule)
        return bool(regex.search(payload))
    except ValueError as e:
        print(f"[ERROR] Invalid PCRE pattern: {pcre_rule}. Error: {e}")
        return False

test_payloads = [
    "GET /admin HTTP/1.1\r\nHost: google.com\r\nUser-Agent: attack_tool\r\n\r\n",
    "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "HEAD /home HTTP/1.1\r\n\r\n"
    """GET /path/to/resource HTTP/1.1
    Host: www.example.com
    User-Agent: TestAgent/1.0
    Accept: */*
    Content-Length: 123
    Connection: keep-alive""",
    "https://example.com/?sessionid=abcdef1234567890abcdef123456",
    "https://example.com/?sid=1234567890abcdef123456abcdef123456",
    "https://example.com/?phpsessid=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
    "https://example.com/?jsessionid=abcde12345abcde67890abcde12345",
    "https://example.com/?asp.net_sessionid=fedcba0987654321abcdef1234567890",
    "SYSTEM 'http://169.254.169.254/latest/meta-data/'",
    "SYSTEM 'http://metadata.google.internal/computeMetadata/v1/'",
    "SYSTEM 'http://169.254.169.254/'",
    "SYSTEM 'http://169.254.169.254'",
]

test_rules = [
    "/User-Agent:\\s*attack_tool/i",  
    "/Host:\\s*example\\.com/m",      
    "/GET\\s+/admin/s",               
    "/bad_pattern",                   
    "/(?i)(sessionid|sid|phpsessid|jsessionid|asp.net_sessionid)=[a-f0-9]{20,}/",
    "/SYSTEM\s+[\"']http:\/\/(169\.254\.169\.254|metadata\.google\.internal)/i",
    "^(?i)(GET|POST|HEAD)\s+/.*\s+HTTP/\d\.\d\r\n((\S+:\s*.*\r\n)+)\r\n$",
]

for rule in test_rules:
    print(f"\nTesting rule: {rule}")
    for payload in test_payloads:
        result = check_payload(payload, rule)
        print(f"Match found: {result}")
