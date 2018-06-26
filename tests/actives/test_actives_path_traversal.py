import pytest
from ava.actives.path_traversal import PathTraversalCheck
from ava.common.exception import InvalidFormatException


@pytest.fixture
def response():
    return type("Request", (object,), {})


class TestPathTraversalCheck:
    payloads = [
        "etc/group",
        "/etc/group",
        "../etc/group",
        "../../etc/group",
        "../../../etc/group",
        "../../../../etc/group",
        "../../../../../etc/group",
        "../../../../../../etc/group",
        "../../../../../../../etc/group",
        "../../../../../../../../etc/group",
        '../../../../../../../../../etc/group'
    ]

    @pytest.fixture
    def check(self):
        return PathTraversalCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_check_true_positive(self, check, response):
        html = "<html><head></head><body>{}</body</html>"

        # true positive
        body = "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:user"
        response.text = html.format(body)
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        html = "<html><head></head><body>{}</body</html>"

        # true negative
        body = "Not found"
        response.text = html.format(body)
        test = check.check(response, check._payloads[0])
        assert not test

        # empty
        response.text = ""
        test = check.check(response, check._payloads[0])
        assert not test

    def test_check_payloads_positive(self, check):
        # positive
        payloads = ["./etc/group"]
        assert payloads == check._check_payloads(payloads)

    def test_check_payloads_negative(self, check):
        # negative
        payloads = ["Invalid payload"]
        with pytest.raises(InvalidFormatException):
            check._check_payloads(payloads)
