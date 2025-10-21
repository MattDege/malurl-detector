from maldet.features import extract_lexical_features


def test_basic_features():
    feats = extract_lexical_features("https://example.com/path?q=1")
    assert feats["len_url"] > 0
    assert feats["count_dots"] >= 1
    assert "has_ip_host" in feats
