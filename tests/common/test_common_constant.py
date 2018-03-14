from ava.common.constant import HTTP


def test_http_method():
    method = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]

    # individual
    assert HTTP.METHOD.GET == method[0]
    assert HTTP.METHOD.POST == method[1]
    assert HTTP.METHOD.PUT == method[2]
    assert HTTP.METHOD.DELETE == method[3]
    assert HTTP.METHOD.PATCH == method[4]
    assert HTTP.METHOD.HEAD == method[5]

    # list
    assert sorted(list(HTTP.METHOD)) == sorted(method)


def test_http_content_type():
    content_type = [
        "text/plain",
        "text/html",
        "application/x-www-form-urlencoded",
        "application/json",
        "multipart/form-data"
    ]

    # individual
    assert HTTP.CONTENT_TYPE.TEXT == content_type[0]
    assert HTTP.CONTENT_TYPE.HTML == content_type[1]
    assert HTTP.CONTENT_TYPE.FORM == content_type[2]
    assert HTTP.CONTENT_TYPE.JSON == content_type[3]
    assert HTTP.CONTENT_TYPE.MULTIPART == content_type[4]

    # list
    assert sorted(list(HTTP.CONTENT_TYPE)) == sorted(content_type)
