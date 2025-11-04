# tests/test_detector.py
from maldet.detector import explain_url, predict_url


def test_predict_basic_scores():
    benign = "https://www.wikipedia.org"
    mal = "http://192.168.0.10/admin"
    label_b, score_b = predict_url(benign)
    label_m, score_m = predict_url(mal)
    assert label_b in (0, 1)
    assert label_m in (0, 1)
    # IP host should generally score higher than a well-known benign site
    assert score_m >= score_b


def test_explain_structure():
    ex = explain_url("http://paypal.com.security-check.xyz/login?session=1")
    assert "score" in ex and "label" in ex and "features" in ex and "contributions" in ex
    assert isinstance(ex["contributions"], dict)
