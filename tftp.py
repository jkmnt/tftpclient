# task-specific custom tftp client library
# to avoid tftpy dependency

from enum import IntEnum
import socket
import struct
import time
import logging

# codes
class Opcode(IntEnum):
    RRQ = 1
    WRQ = 2
    DATA = 3
    ACK = 4
    ERR = 5
    OACK = 6

class Errcode(IntEnum):
    CUSTOM = 0
    FILE_NOT_FOUND = 1
    ACCESS_VIOLATION = 2
    DISK_FULL = 3
    ILLEGAL_OPERATION = 4
    UNKNOWN_TID = 5
    FILE_ALREADY_EXISTS = 6
    NO_SUCH_USER = 7
    NO_OPTIONS_ERROR = 8


class TFTPClientError(Exception):
    pass

class TFTPClientCustomError(TFTPClientError):
    pass

class TFTPClientFileNotFoundError(TFTPClientError):
    pass

class TFTPClientAccessViolationError(TFTPClientError):
    pass

class TFTPClientDiskFullError(TFTPClientError):
    pass

class TFTPClientIllegalOperationError(TFTPClientError):
    pass


# handy utils

def cstr(s):
    return bytes(s, 'ascii') + b'\0'

def create_data_pkt(blocknum, data):
    return struct.pack('! H H', Opcode.DATA, blocknum) + data

def create_ack_pkt(acknum):
    return struct.pack('! H H', Opcode.ACK, acknum)

def create_err_pkt(errcode, msg=''):
    return struct.pack('! H H s', Opcode.ERR, errcode, cstr(msg))

def create_rq_pkt(filename, op, options=None):
    pkt = struct.pack('! H', op) + cstr(filename) + cstr('octet')
    if options:
        pkt += b''.join([cstr(k) + cstr(v) for k, v in options.items()])
    return pkt

def create_wrq_pkt(filename, blocksize, timeout):
    return create_rq_pkt(filename, Opcode.WRQ, {'blksize':str(blocksize), 'timeout':str(timeout)})

def create_rrq_pkt(filename, blocksize, timeout):
    return create_rq_pkt(filename, Opcode.RRQ, {'blksize':str(blocksize), 'timeout':str(timeout)})


# the options are kv pairs, each word is \0 terminated
def parse_options(src):
    src = str(src, 'ascii')
    words = src.strip().split('\0')
    options = {k.lower():v for k, v in zip(words[0::2], words[1::2])}
    return options


# NOTE: call to parse should be wrapped in try block
def parse_pkt(src):
    op, = struct.unpack_from('! H', src)
    if op == Opcode.DATA:
        blocknum, = struct.unpack_from('! H', src, 2)
        return {'op': Opcode.DATA, 'blocknum': blocknum, 'data': src[4:]}
    elif op == Opcode.ACK:
        acknum, = struct.unpack_from('! H', src, 2)
        return {'op': Opcode.ACK, 'acknum': acknum}
    elif op == Opcode.ERR:
        errcode, = struct.unpack_from('! H', src, 2)
        return {'op': Opcode.ERR, 'errcode': errcode, 'msg': str(src[4:], 'ascii').rstrip('\0')}
    elif op == Opcode.OACK:
        options = parse_options(src[2:])
        return {'op': Opcode.OACK, 'options': options}
    else:
        return {'op': op}


class TFTPClient:
    def __init__(self, ip, port, timeout=1, connect_timeout=5, session_timeout=10, blocksize=1468):
        self.sock = None
        self.connect_timeout = connect_timeout
        self.session_timeout = session_timeout
        self.def_timeout = timeout
        self.def_blocksize = blocksize
        self.ip = ip
        self.connect_port = port
        self.port = None


    def txrx(self, tx, handle_rx, timeout):
        sock = self.sock
        sock.settimeout(self.timeout)
        start = time.time()
        while True:
            now = time.time()
            if now - start > timeout:
                raise TFTPClientError('timeout')

            sock.sendto(tx, (self.ip, self.port))

            rxstart = time.time()
            try:
                data, remote = sock.recvfrom(2048)
            except socket.timeout:
                continue
            rxend = time.time()

            try:
                rx = parse_pkt(data)
            except:
                logging.exception('parse error')
            else:
                if remote[0] == self.ip:
                    resp = handle_rx(rx)
                    if resp:
                        return resp, remote
            # sleep more, avoid resend if woke up prematurely
            time.sleep(rxstart + self.timeout - rxend)


    def process_err(self, rx):
        if rx['op'] == Opcode.ERR:
            errcode = rx['errcode']
            msg = rx['msg']
            if errcode == Errcode.ACCESS_VIOLATION:
                raise TFTPClientAccessViolationError(msg)
            elif errcode == Errcode.CUSTOM:
                raise TFTPClientCustomError(msg)
            elif errcode == Errcode.DISK_FULL:
                raise TFTPClientDiskFullError(msg)
            elif errcode == Errcode.FILE_NOT_FOUND:
                raise TFTPClientFileNotFoundError(msg)
            elif errcode == Errcode.ILLEGAL_OPERATION:
                raise TFTPClientIllegalOperationError(msg)
            else:
                raise TFTPClientError('Server error %s %s' % (str(errcode), msg))

    def process_unhandled(self, rx):
        raise TFTPClientError('Unexpected packet %s' % str(rx['op']))


    def handle_read_connect(self, rx):
        self.process_err(rx)
        if rx['op'] == Opcode.OACK:
            return rx
        if rx['op'] == Opcode.DATA:
            if rx['blocknum'] == 1:
                return rx
            return None
        self.process_unhandled(rx)


    def handle_write_connect(self, rx):
        self.process_err(rx)
        if rx['op'] == Opcode.OACK:
            return rx
        if rx['op'] == Opcode.ACK:
            if rx['blocknum'] == 0:
                return rx
            return None
        self.process_unhandled(rx)


    def handle_data_rx(self, rx):
        self.process_err(rx)
        if rx['op'] == Opcode.DATA:
            if rx['blocknum'] == self.blocknum + 1:
                return rx
            return None
        self.process_unhandled(rx)


    def handle_data_tx(self, rx):
        self.process_err(rx)
        if rx['op'] == Opcode.ACK:
            if rx['acknum'] == self.blocknum:
                return rx
            return None
        self.process_unhandled(rx)


    def setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.blocknum = 0
        self.blocksize = 512
        self.timeout = 1
        self.port = self.connect_port


    def accept_options(self, oack):
        try:
            options = oack['options']
            if 'blksize' in options:
                bs = int(options['blksize'])
                if (64 <= bs <= 1468):
                    self.blocksize = bs
                else:
                    raise TFTPClientError('Unacceptable blocksize %d', bs)
            if 'timeout' in options:
                tout = int(options['timeout'])
                if (1 <= tout <= self.session_timeout):
                    self.timeout = tout
        except:
            raise TFTPClientError('Unacceptable options')


    def connect(self, remote):
        self.sock.connect(remote)
        self.port = remote[1]


    def read(self, filename):
        self.setup()

        buf = b''

        pkt = create_rrq_pkt(filename, self.def_blocksize, self.def_timeout)
        resp, remote = self.txrx(pkt, self.handle_read_connect, self.connect_timeout)
        if resp['op'] == Opcode.OACK:
            self.accept_options(resp)
        else: # data
            self.blocknum = 1
            buf += resp['data']

        # the response may come from another port. 'connect' to it
        self.connect(remote)

        while True:
            ack = create_ack_pkt(self.blocknum)
            resp,remote = self.txrx(ack, self.handle_data_rx, self.session_timeout)
            buf += resp['data']
            self.blocknum += 1
            if len(resp['data']) < self.blocksize:
                ack = create_ack_pkt(self.blocknum)
                self.sock.send(ack)
                return buf


    def write(self, filename, buf):
        self.setup()

        pkt = create_wrq_pkt(filename, self.def_blocksize, self.def_timeout)
        resp, remote = self.txrx(pkt, self.handle_write_connect, self.connect_timeout)
        if resp['op'] == Opcode.OACK:
            self.accept_options(resp)

        self.connect(remote)

        while True:
            self.blocknum += 1;
            chunk = buf[:self.blocksize]
            buf = buf[self.blocksize:]
            tx = create_data_pkt(self.blocknum, chunk)
            resp, remote = self.txrx(tx, self.handle_data_tx, self.session_timeout)

            if len(chunk) < self.blocksize:
                return
