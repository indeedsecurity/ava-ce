import pytest
from ava.common.exception import InvalidFormatException
from ava.parsers.multipart import MultipartForm
from requests_toolbelt import MultipartDecoder


class TestMultipartForm:

    @pytest.fixture
    def multiparts(self):
        content_type = "multipart/form-data; boundary=boundary"
        multipart_data = [
            ('--boundary\r\n'
             'Content-Disposition: form-data; name="ava"\r\n\r\n'
             'avascan\r\n'
             '--boundary--\r\n'),
            ('--boundary\r\n'
             'Content-Disposition: form-data; name="ava"; filename="data.txt"\r\n\r\n'
             'avascan\r\n'
             '--boundary--\r\n'),
            ('--boundary\r\n'
             'Content-Disposition: form-data; name="ava"; filename="data.txt"\r\n'
             'Content-Type: text/plain\r\n\r\n'
             'avascan\r\n'
             '--boundary--\r\n'),
            ('--boundary\r\n'
             'Content-Disposition: form-data; name="ava"; filename="data.txt"\r\n'
             'Content-Type: text/plain\r\n'
             'X-Custom-Header: token\r\n\r\n'
             'avascan\r\n'
             '--boundary--\r\n')
        ]

        return content_type, multipart_data

    def test_init(self, multiparts):
        content_type = multiparts[0]
        multipart_data = multiparts[1]

        # value
        test = MultipartForm(multipart_data[0], content_type)
        assert test._parts == {'ava': "avascan"}

        # file with filename
        test = MultipartForm(multipart_data[1], content_type)
        assert test._parts == {'ava': ["data.txt", "avascan"]}

        # file with content-type
        test = MultipartForm(multipart_data[2], content_type)
        assert test._parts == {'ava': ["data.txt", "avascan", "text/plain"]}

        # file with custom headers
        test = MultipartForm(multipart_data[3], content_type)
        assert test._parts == {'ava': ["data.txt", "avascan", "text/plain", {'X-Custom-Header': "token"}]}

    def test_parse_multipart_positive(self, multiparts):
        content_type = multiparts[0]
        multipart_data = multiparts[1]

        # value
        parsed = MultipartForm(multipart_data[0], content_type)
        test = parsed._parse_multipart(multipart_data[0], content_type)
        assert isinstance(test, MultipartDecoder)

        # file with filename
        parsed = MultipartForm(multipart_data[1], content_type)
        test = parsed._parse_multipart(multipart_data[1], content_type)
        assert isinstance(test, MultipartDecoder)

    def test_parse_multipart_negative(self, multiparts):
        content_type = multiparts[0]
        multipart_data = multiparts[1]
        parsed = MultipartForm(multipart_data[0], content_type)

        # invalid multipart data
        with pytest.raises(InvalidFormatException):
            parsed._parse_multipart("invalid data", content_type)

        # invalid multipart content-type
        with pytest.raises(InvalidFormatException):
            parsed._parse_multipart(multipart_data[0], "text/plain")

        # missing content-type boundary
        with pytest.raises(InvalidFormatException):
            parsed._parse_multipart(multipart_data[0], "multipart/form-data;")

    def test_parse_content_disposition_positive(self, multiparts):
        parsed = MultipartForm(multiparts[1][0], multiparts[0])

        # name
        headers = {b'Content-Disposition': b'form-data; name="ava"'}
        test = parsed._parse_content_disposition(headers)
        assert test == ("ava", None)

        # filename
        headers = {b'Content-Disposition': b'form-data; name="ava"; filename="data.txt"'}
        test = parsed._parse_content_disposition(headers)
        assert test == ("ava", "data.txt")

    def test_parse_content_disposition_negative(self, multiparts):
        parsed = MultipartForm(multiparts[1][0], multiparts[0])

        # empty name
        headers = {b'Content-Disposition': b'form-data; name=""'}
        test = parsed._parse_content_disposition(headers)
        assert test == ("", None)

        # empty filename
        headers = {b'Content-Disposition': b'form-data; name="ava"; filename=""'}
        test = parsed._parse_content_disposition(headers)
        assert test == ("ava", "")

    def test_parse_content_type(self, multiparts):
        parsed = MultipartForm(multiparts[1][0], multiparts[0])

        # with content-type
        headers = {b'Content-Type': b"application/pdf"}
        test = parsed._parse_content_type(headers)
        assert test == "application/pdf"

        # without content-type
        headers = {}
        test = parsed._parse_content_type(headers)
        assert test is None

    def test_replace_at(self, multiparts):
        content_type = multiparts[0]
        multipart_data = multiparts[1]

        # value
        parsed = MultipartForm(multipart_data[0], content_type)
        test = parsed._replace_at("ava", "replaced")
        assert test == multipart_data[0].replace("avascan", "replaced")

        # file with filename
        parsed = MultipartForm(multipart_data[1], content_type)
        test = parsed._replace_at("ava", "replaced")
        assert test == multipart_data[1].replace("avascan", "replaced")

        # file with content-type
        parsed = MultipartForm(multipart_data[2], content_type)
        test = parsed._replace_at("ava", "replaced")
        assert test == multipart_data[2].replace("avascan", "replaced")

        # file with custom headers
        parsed = MultipartForm(multipart_data[3], content_type)
        test = parsed._replace_at("ava", "replaced")
        assert test == multipart_data[3].replace("avascan", "replaced")

    def test_replace_positive(self, multiparts):
        content_type = multiparts[0]
        multipart_data = multiparts[1]

        # value
        parsed = MultipartForm(multipart_data[0], content_type)
        test = parsed.replace("ava", "replaced")
        assert test == multipart_data[0].replace("avascan", "replaced")

        # file with filename
        parsed = MultipartForm(multipart_data[1], content_type)
        test = parsed.replace("ava", "replaced")
        assert test == multipart_data[1].replace("avascan", "replaced")

    def test_replace_negative(self, multiparts):
        # invalid name
        with pytest.raises(KeyError):
            parsed = MultipartForm(multiparts[1][0], multiparts[0])
            parsed.replace("invalid", "replaced")

    def test_names(self, multiparts):
        content_type = multiparts[0]
        multipart_data = multiparts[1]

        # value
        parsed = MultipartForm(multipart_data[0], content_type)
        test = parsed.names()
        assert test == {'ava': "avascan"}

        # file with filename
        parsed = MultipartForm(multipart_data[1], content_type)
        test = parsed.names()
        assert test == {'ava': "avascan"}

        # file with content-type
        parsed = MultipartForm(multipart_data[2], content_type)
        test = parsed.names()
        assert test == {'ava': "avascan"}

        # file with custom headers
        parsed = MultipartForm(multipart_data[3], content_type)
        test = parsed.names()
        assert test == {'ava': "avascan"}
