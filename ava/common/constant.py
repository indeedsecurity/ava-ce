from collections import namedtuple


"""
HTTP method constants, such as GET, POST, and PUT. Dictionary keys are names and values are constants. These are added
to the HTTP constant. Exposed as HTTP.METHOD.*, for instance HTTP.METHOD.GET or HTTP.METHOD.POST.
"""
_METHOD = {
    'GET': "GET",
    'POST': "POST",
    'PUT': "PUT",
    'DELETE': "DELETE",
    'PATCH': "PATCH",
    'HEAD': "HEAD"
}


"""
HTTP content-type constants, such as application/* or text/*. Dictionary keys are names and values are constants. These
are added to the HTTP constant. Exposed as HTTP.CONTENT_TYPE.*, for instance HTTP.CONTENT_TYPE.FORM.
"""
_CONTENT_TYPE = {
    'TEXT': "text/plain",
    'HTML': "text/html",
    'FORM': "application/x-www-form-urlencoded",
    'JSON': "application/json",
    'MULTIPART': "multipart/form-data"
}


"""
HTTP namespace. This adds methods and content-types to the HTTP constant.
"""
# HTTP namespace
_HTTP = {
    'METHOD': namedtuple("Method", list(_METHOD))(**_METHOD),
    'CONTENT_TYPE': namedtuple("ContentType", list(_CONTENT_TYPE))(**_CONTENT_TYPE)
}


"""
HTTP constant. This exposes the constant. Constants can be accessed as HTTP.METHOD.* or HTTP.CONTENT_TYPE.*.
"""
# HTTP constants
HTTP = namedtuple("Http", list(_HTTP))(**_HTTP)
