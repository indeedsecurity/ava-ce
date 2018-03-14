from copy import copy, deepcopy
from requests_toolbelt import MultipartDecoder, MultipartEncoder
from requests_toolbelt import ImproperBodyPartContentException, NonMultipartContentTypeException
from email.parser import HeaderParser
from ava.common.exception import InvalidFormatException


class MultipartForm:
    """
    Parser to decode multipart form data and replace parts with a given value. Parts can be referenced according to
    the name parameter in their Content-Disposition header.
    """

    def __init__(self, multipart_string, content_type):
        """Parse and format parts"""
        self._parts = {}
        self._decoder = self._parse_multipart(multipart_string, content_type)
        self._boundary = self._decoder.boundary.decode()

        # update parts
        self._update_parts()

    def _parse_multipart(self, multipart_string, content_type):
        """
        Parse multipart data string and return decoder object.
        :param multipart_string: multipart data string
        :param content_type: content-type string
        :return: Multipart decoder
        """
        # parse
        try:
            decoder = MultipartDecoder(multipart_string.encode(), content_type)
        except ImproperBodyPartContentException:
            raise InvalidFormatException("Unable to parse multipart form data")
        except (NonMultipartContentTypeException, AttributeError):
            raise InvalidFormatException("Unable to parse multipart content-type")

        return decoder

    def _update_parts(self):
        """
        Convert each decoder part to name-field pairs and add to the parts dictionary. Fields can be either a string
        or list. Parts with only values are string fields. Parts with files are list fields where the list contains
        the file name, file content, content-type, and custom headers.
        """
        # check each part
        for part in self._decoder.parts:
            headers = copy(part.headers)

            # parse content-disposition and content-type
            name, filename = self._parse_content_disposition(headers)
            content_type = self._parse_content_type(headers)

            # set field; must check None
            # value
            if filename is None:
                field = part.text
            # file with filename
            elif content_type is None:
                field = [filename, part.text]
            # file with content-type
            elif not headers:
                field = [filename, part.text, content_type]
            # file with custom headers
            else:
                custom = {key.decode(): value.decode() for key, value in headers.items()}
                field = [filename, part.text, content_type, custom]

            self._parts[name] = field

    def _parse_content_disposition(self, headers):
        """
        Parse the content-disposition header and return the name and filename parameters. Content-disposition is
        deleted from the headers after retrieving its value. Filename is set to None, if it is not found.
        :param headers: headers for part
        :return: name string and filename string or None
        """
        name = 'Content-Disposition'

        # get content-disposition header
        content_disposition = name + ': ' + headers.pop(name.encode()).decode()

        # parse string for params
        message = HeaderParser().parsestr(content_disposition)
        params = dict(message.get_params(header=name))

        # get name and filename
        name = params['name']
        filename = params.get('filename')

        return name, filename

    def _parse_content_type(self, headers):
        """
        Parse the content-type header and return its value. Content-Type header is deleted from the headers after
        retrieving its value. Content-type is returned as None, if it is not found.
        :param headers: headers for part
        :return: content-type string or None
        """
        name = 'Content-Type'

        # get content-type
        content_type = headers.pop(name.encode(), None)

        # check value; must check None
        if content_type is not None:
            return content_type.decode()

    def _replace_at(self, name, value):
        """
        Replace the part for the given name with the given value and return the multipart data as a string. The
        original parts are not changed.
        :param name: name as string
        :param value: value as string
        :return: multipart data as string
        """
        # copy
        parts = deepcopy(self._parts)

        # replace text
        if isinstance(parts[name], list):
            parts[name][1] = value
        else:
            parts[name] = value

        # encode
        encoder = MultipartEncoder(parts, boundary=self._boundary)
        replacement = encoder.to_string().decode()

        return replacement

    def replace(self, name, value):
        """
        Replace the part for the given name with the given value and return the multipart data as a string. The
        original parts are not changed. KeyError is raised if the name is not valid.
        :param name: name as string
        :param value: value as string
        :return: multipart data as string
        """
        # check name
        if name not in self._parts:
            raise KeyError

        # replace
        replacement = self._replace_at(name, value)

        return replacement

    def names(self):
        """
        Convert name-field parts to name-text pairs and return as a dictionary. Keys can be used to reference parts
        when calling replace().
        :return: name-text pairs as dictionary
        """
        # convert to name-text pairs
        items = self._parts.items()
        names = {name: field[1] if isinstance(field, list) else field for name, field in items}

        return names
