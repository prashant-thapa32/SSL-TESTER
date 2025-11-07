from ssl_tester.scanner import scan_ssl

def test_basic_scan():
    result = scan_ssl("google.com", 443)
    assert "protocol" in result
    assert "certificate" in result

