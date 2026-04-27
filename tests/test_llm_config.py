from app.routes.llm_config import _extract_content


def test_extract_content_reads_choices_message_content():
    payload = {"choices": [{"message": {"content": "hello"}}]}
    assert _extract_content(payload) == "hello"


def test_extract_content_reads_responses_style_output():
    payload = {
        "output": [
            {
                "content": [
                    {"type": "output_text", "text": "first line"},
                    {"type": "output_text", "text": "second line"},
                ]
            }
        ]
    }
    assert _extract_content(payload) == "first line\nsecond line"


def test_extract_content_raises_when_text_missing():
    payload = {"choices": [{"message": {"content": []}}]}
    try:
        _extract_content(payload)
    except ValueError as exc:
        assert "no readable text" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError for empty provider content")
