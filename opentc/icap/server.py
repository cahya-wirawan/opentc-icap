#!/bin/env python
# -*- coding: utf8 -*-

import os
import re
import magic
import socketserver
import multipart
import logging.config
import traceback
import json
import textract
import tempfile
from urllib.parse import urlparse
from multipart.multipart import parse_options_header
from pyicap import ICAPServer, BaseICAPRequestHandler


class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass


class ICAPHandler(BaseICAPRequestHandler):
    logger = logging.getLogger(__name__)
    remove_newline = re.compile(b'\r?\n')
    forbidden_list = []

    def opentc_resp_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'RESPMOD')
        self.set_icap_header(b'Preview', b'0')
        self.send_headers(False)

    def opentc_resp_RESPMOD(self):
        self.no_adaptation_required()

    def opentc_req_OPTIONS(self):
        try:
            response = self.server.opentc["client"].ping()
            response = json.loads(response.decode('utf-8'))
            if response["status"] == "OK":
                self.logger.debug("OPTIONS Ping response: {}".format(response))
            else:
                self.logger.debug("OPTIONS Ping response: the OpenTC server is not responding")
        except BrokenPipeError as err:
            self.logger.error("Exception: {}".format(err))
            self.logger.error(traceback.format_exc())
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD')
        self.set_icap_header(b'Service', b'PyICAP Server 1.0')
        self.send_headers(False)

    def opentc_req_REQMOD(self):
        self.multipart_data = None
        self.last_form_field = None
        self.big_chunk = b''
        self.content_analysis_results = dict()

        def on_part_begin():
            self.multipart_data = dict()
            self.multipart_data[b'Content'] = b''
            self.logger.debug("on_part_begin")

        def on_part_data(data, start, end):
            self.multipart_data[b'Content'] += data[start:end]
            self.logger.debug("on_part_data")

        def on_part_end():
            self.logger.debug("on_part_end")
            for key in self.multipart_data:
                if key == b'Content':
                    mime_type = magic.from_buffer(self.multipart_data[b'Content'], mime=True)
                    self.logger.debug("Content mime_type: {}".format(mime_type))
                    if b'Content-Type' in self.multipart_data:
                        # content_type = [ct.strip() for ct in self.multipart_data[b'Content-Type'].split(b';')]
                        content_type = [mime_type]
                        content_disposition = {'name': '', 'filename': ''}
                        for x in self.multipart_data[b'Content-Disposition'].split(b';'):
                            if b'=' in x:
                                key, value = x.split(b'=')
                                key = key.decode("utf-8").strip(" \"")
                                value = value.decode("utf-8").strip(" \"")
                                content_disposition[key] = value

                        print(content_disposition)
                        result = self.content_analyse(
                            converter=self.server.opentc["config"]["converter"],
                            content_disposition=content_disposition,
                            content_type=content_type, content=self.multipart_data[b'Content'],
                            content_min_length=self.server.opentc["config"]["content_min_length"],
                            client=self.server.opentc["client"])
                        name = self.multipart_data[b'Content-Disposition'].split(b';')[1].split(b'=')[1]

                        self.content_analysis_results[name.decode("utf-8").replace('"', '')] = result
                else:
                    self.logger.debug("{}: {}".format(key, self.multipart_data[key]))
            return

        def on_header_field(data, start, end):
            self.last_form_field = data[start:end]
            self.logger.debug("on_header_field")

        def on_header_value(data, start, end):
            self.multipart_data[self.last_form_field] = data[start:end]
            self.logger.debug("on_header_value")

        def on_end():
            self.logger.debug("on_end")

        self.set_icap_response(200)

        url = urlparse(self.enc_req[1])
        if len(ICAPHandler.forbidden_list) == 0:
            for forbidden_content in self.server.opentc["config"]["forbidden_content_list"]:
                ICAPHandler.forbidden_list.append(re.compile(forbidden_content.encode("utf-8")))
        match_string = self.check_content(ICAPHandler.forbidden_list, url.query)
        if match_string:
            self.reject_request(match_string.decode("utf-8"))
            return

        # self.set_enc_request(b' '.join(self.enc_req))
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                self.set_enc_header(h, v)

        # Copy the request body (in case of a POST for example)
        if not self.has_body:
            self.set_enc_request(b' '.join(self.enc_req))
            self.send_headers(False)
            return
        if self.preview:
            prevbuf = b''
            while True:
                chunk = self.read_chunk()
                if chunk == b'':
                    break
                prevbuf += chunk
            if self.ieof:
                self.send_headers(True)
                if len(prevbuf) > 0:
                    self.write_chunk(prevbuf)
                self.write_chunk(b'')
                return
            self.cont()
            self.set_enc_request(b' '.join(self.enc_req))
            self.send_headers(True)
            if len(prevbuf) > 0:
                self.write_chunk(prevbuf)
            while True:
                chunk = self.read_chunk()
                self.write_chunk(chunk)
                if chunk == b'':
                    break
        else:
            # Parse the Content-Type header to get the multipart boundary.
            content_type, params = parse_options_header(self.enc_req_headers[b'content-type'][0])
            content_type = [content_type.decode("utf-8")]
            self.logger.debug("Content-type: {}".format(content_type[0]))
            boundary = params.get(b'boundary')
            parser = None
            if boundary is not None:
                # Callbacks dictionary.
                callbacks = {
                    'on_part_begin': on_part_begin,
                    'on_part_data': on_part_data,
                    'on_part_end': on_part_end,
                    'on_header_field': on_header_field,
                    'on_header_value': on_header_value,
                    'on_end': on_end
                }
                parser = multipart.MultipartParser(boundary, callbacks)

            while True:
                chunk = self.read_chunk()
                if chunk == b'':
                    break
                self.big_chunk += chunk

            match_string = self.check_content(ICAPHandler.forbidden_list, url.path)
            if match_string:
                self.reject_request(match_string.decode("utf-8"))
                return

            if boundary is not None:
                size = len(self.big_chunk)
                start = 0
                while size > 0:
                    end = min(size, 1024 * 1024)
                    parser.write(self.big_chunk[start:end])
                    size -= end
                    start = end
            else:
                result = self.content_analyse(
                    converter=self.server.opentc["config"]["converter"],
                    content_type=content_type, content=self.big_chunk,
                    content_min_length=self.server.opentc["config"]["content_min_length"],
                    client=self.server.opentc["client"])
                name = "text"
                self.content_analysis_results[name] = result

            is_allowed = True
            for result in self.content_analysis_results:
                if self.content_analysis_results[result] is None:
                    continue
                for classifier in self.server.opentc["config"]["classifier_status"]:
                    if self.server.opentc["config"]["classifier_status"][classifier] is False:
                        continue
                    for restricted_class in self.server.opentc["config"]["restricted_classes"]:
                        self.logger.debug("{}: result:{}, classifier:{}".format(restricted_class, result, classifier))
                        if restricted_class in self.content_analysis_results[result][classifier]:
                            is_allowed = False
                            break
                        else:
                            is_allowed = True
                    if is_allowed is True:
                        break
                if is_allowed is False:
                    break
            if is_allowed:
                self.set_enc_request(b' '.join(self.enc_req))
                self.send_headers(True)
                self.write_chunk(self.big_chunk)
            else:
                content = json.dumps(self.content_analysis_results)
                content = "result={}".format(content).encode("utf-8")
                enc_req = self.enc_req[:]
                enc_req[0] = self.server.opentc["config"]["replacement_http_method"].encode("utf-8")
                enc_req[1] = self.server.opentc["config"]["replacement_url"].encode("utf-8")
                self.set_enc_request(b' '.join(enc_req))
                self.enc_headers[b"content-type"] = [b"application/x-www-form-urlencoded"]
                self.enc_headers[b"content-length"] = [str(len(content)).encode("utf-8")]
                self.send_headers(True)
                self.write_chunk(content)

    def content_analyse(self, content_disposition=None, content_type=None, content=None,
                        content_min_length=50, client=None,
                        converter=None):
        if content_type is None or content is None or client is None:
            return None
        self.logger.debug("content_analyse {}".format(content_type[0]))
        if len(content) < content_min_length:
            result = None
            self.logger.debug("content_analyse content_min_length < {}".format(content_min_length))
            return result
        if content_type[0] in converter and converter[content_type[0]] == "text":
            content = self.convert_to_text(content=content, converter=converter[content_type[0]])
        elif content_type[0] in converter and converter[content_type[0]] == "textract":
            with tempfile.TemporaryDirectory() as tmpdirname:
                path = os.path.join(tmpdirname, content_disposition["filename"])
                with open(path, "wb") as f:
                    f.write(content)
                content = self.convert_to_text(path=path, converter=converter[content_type[0]])
        else:
            return None
        if content is None:
            return None
        response = client.predict_stream(content)
        if response is None:
            return None
        result = json.loads(response.decode('utf-8'))["result"]
        self.logger.debug("content_analyse predict_stream result: {}".format(result))
        return result

    def convert_to_text(self, path=None, content=None, converter=None):
        if converter == "text":
            result = self.remove_newline.sub(b' ', content)
            return result
        elif converter == "textract":
            result = textract.process(path)
            result = self.remove_newline.sub(b' ', result)
            return result
        else:
            return None

    def log_message(self, format, *args):
        # Override the pyicap logger function
        self.logger.debug("{}: {}".format(self.client_address[0], args))

    def check_content(self, forbidden_list, content):
        for forbidden in forbidden_list:
            forbidden_match = forbidden.search(content)
            if forbidden_match:
                return forbidden_match.group(0)
        return None

    def reject_request(self, found_data):
        content = "result={}".format(found_data).encode("utf-8")
        enc_req = self.enc_req[:]
        enc_req[0] = self.server.opentc["config"]["forbidden_http_method"].encode("utf-8")
        enc_req[1] = self.server.opentc["config"]["forbidden_url"].encode("utf-8")
        self.set_enc_request(b' '.join(enc_req))
        self.enc_headers[b"content-type"] = [b"application/x-www-form-urlencoded"]
        self.enc_headers[b"content-length"] = [str(len(content)).encode("utf-8")]
        self.send_headers(True)
        self.write_chunk(content)
        return
