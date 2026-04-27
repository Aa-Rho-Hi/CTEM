from app.routes._shared import STANDARD_ERROR_RESPONSES, bad_request, conflict, not_found, unauthorized


def test_standard_error_helpers_return_expected_statuses():
    assert bad_request("x").status_code == 400
    assert unauthorized("x").status_code == 401
    assert not_found("x").status_code == 404
    assert conflict("x").status_code == 409


def test_standard_error_responses_include_common_statuses():
    for code in (400, 401, 403, 404, 409, 422, 503):
        assert code in STANDARD_ERROR_RESPONSES
