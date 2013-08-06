# -*- coding: iso-8859-15 -*-
import socket
import struct
import base64
import inspect
from socksipy import socks


class Mrim:
    port = 443
    server = 'mrim.mail.ru'
    behaviour = 1
    bind_cn = True
    ping_time = 30
    timeout = 5
    email = ''
    nickname = ''
    user_agent = 'MRA 5.6 (build 3402);'
    user_agent_descr = 'client=\"magent\" version=\"5.6\" build=\"3402\"'
    sock = None
    cn1 = None
    cn2 = None
    mnumb = 0
    groups = 0
    password = None
    proxy = "10.60.3.150"
    proxy_port = 3128
    status = None
    xstatus = None
    xstatus_text = None
    proxy_type = None
    proxy_user = None
    proxy_pass = None
    ip = None
    base = None
    CS_MAGIC = 0xDEADBEEF
    PROTO_VERSION = 0x00010013
    CONTACT_FLAG_GROUP = 0x02
    CONTACT_FLAG_IGNORE = 0x10
    CONTACT_FLAG_INVISIBLE = 0x04
    CONTACT_FLAG_REMOVED = 0x01
    CONTACT_FLAG_SHADOW = 0x20
    CONTACT_FLAG_SMS = 0x100000
    CONTACT_FLAG_VISIBLE = 0x08
    CONTACT_INTFLAG_NOT_AUTHORIZED = 0x01
    CONTACT_OPER_ERROR = 0x01
    CONTACT_OPER_GROUP_LIMIT = 0x6
    CONTACT_OPER_INTERR = 0x02
    CONTACT_OPER_INVALID_INFO = 0x04
    CONTACT_OPER_NO_SUCH_USER = 0x03
    CONTACT_OPER_SUCCESS = 0x00
    CONTACT_OPER_USER_EXISTS = 0x05
    FILE_TRANSFER_MIRROR = 4
    FILE_TRANSFER_STATUS_DECLINE = 0
    FILE_TRANSFER_STATUS_ERROR = 2
    FILE_TRANSFER_STATUS_INCOMPATIBLE_VERS = 3
    FILE_TRANSFER_STATUS_OK = 1
    GET_CONTACTS_ERROR = 0x01
    GET_CONTACTS_INTERR = 0x02
    GET_CONTACTS_OK = 0x00
    LOGOUT_NO_RELOGIN_FLAG = 0x10
    MAX_CLIENT_DESCRIPTION = 256
    MESSAGE_DELIVERED = 0x00
    MESSAGE_FLAG_ALARM = 0x4000
    MESSAGE_FLAG_AUTHORIZE = 0x08
    MESSAGE_FLAG_CONTACT = 0x0200
    MESSAGE_FLAG_MULTICAST = 0x1000
    MESSAGE_FLAG_NORECV = 0x04
    MESSAGE_FLAG_NOTIFY = 0x0400
    MESSAGE_FLAG_OFFLINE = 0x01
    MESSAGE_FLAG_OLD = 0x200000
    MESSAGE_FLAG_RTF = 0x80
    MESSAGE_FLAG_SMS = 0x0800
    MESSAGE_FLAG_SMS_NOTIFY = 0x2000
    MESSAGE_FLAG_SPAM = 0x010000
    MESSAGE_FLAG_SYSTEM = 0x40
    MESSAGE_FLAG_UNI = 0x100000
    MESSAGE_REJECTED_DENY_OFFMSG = 0x8006
    MESSAGE_REJECTED_INTERR = 0x8003
    MESSAGE_REJECTED_LIMIT_EXCEEDED = 0x8004
    MESSAGE_REJECTED_NOUSER = 0x8001
    MESSAGE_REJECTED_TOO_LARGE = 0x8005
    MESSAGE_USERFLAGS_MASK = 0x36A8
    MRIM_ANKETA_INFO_STATUS_DBERR = 2
    MRIM_ANKETA_INFO_STATUS_NOUSER = 0
    MRIM_ANKETA_INFO_STATUS_OK = 1
    MRIM_ANKETA_INFO_STATUS_RATELIMERR = 3
    MRIM_CS_ADD_CONTACT = 0x1019
    MRIM_CS_ADD_CONTACT_ACK = 0x101A
    MRIM_CS_ANKETA_INFO = 0x1028
    MRIM_CS_AUTHORIZE = 0x1020
    MRIM_CS_AUTHORIZE_ACK = 0x1021
    MRIM_CS_CHANGE_STATUS = 0x1022
    MRIM_CS_CONNECTION_PARAMS = 0x1014
    MRIM_CS_CONTACT_LIST2 = 0x1037
    MRIM_CS_DELETE_OFFLINE_MESSAGE = 0x101E
    MRIM_CS_FILE_TRANSFER = 0x1026
    MRIM_CS_FILE_TRANSFER_ACK = 0x1027
    MRIM_CS_GET_MPOP_SESSION = 0x1024
    MRIM_CS_HELLO = 0x1001
    MRIM_CS_HELLO_ACK = 0x1002
    MRIM_CS_LOGIN_ACK = 0x1004
    MRIM_CS_LOGIN_REJ = 0x1005
    MRIM_CS_LOGIN2 = 0x1038
    MRIM_CS_LOGOUT = 0x1013
    MRIM_CS_MAILBOX_STATUS = 0x1033
    MRIM_CS_MESSAGE = 0x1008
    MRIM_CS_MESSAGE_ACK = 0x1009
    MRIM_CS_MESSAGE_RECV = 0x1011
    MRIM_CS_MESSAGE_STATUS = 0x1012
    MRIM_CS_MODIFY_CONTACT = 0x101B
    MRIM_CS_MODIFY_CONTACT_ACK = 0x101C
    MRIM_CS_MPOP_SESSION = 0x1025
    MRIM_CS_NEW_EMAIL = 0x1048
    MRIM_CS_OFFLINE_MESSAGE_ACK = 0x101D
    MRIM_CS_PING = 0x1006
    MRIM_CS_SMS = 0x1039
    MRIM_CS_SMS_ACK = 0x1040
    MRIM_CS_USER_INFO = 0x1015
    MRIM_CS_USER_STATUS = 0x100F
    MRIM_CS_WP_REQUEST = 0x1029
    MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY = 6
    MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_DAY = 14
    MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_MONTH = 13
    MRIM_CS_WP_REQUEST_PARAM_CITY_ID = 11
    MRIM_CS_WP_REQUEST_PARAM_COUNTRY_ID = 15
    MRIM_CS_WP_REQUEST_PARAM_DATE1 = 7
    MRIM_CS_WP_REQUEST_PARAM_DATE2 = 8
    MRIM_CS_WP_REQUEST_PARAM_DOMAIN = 1
    MRIM_CS_WP_REQUEST_PARAM_FIRSTNAME = 3
    MRIM_CS_WP_REQUEST_PARAM_LASTNAME = 4
    MRIM_CS_WP_REQUEST_PARAM_MAX = 16
    MRIM_CS_WP_REQUEST_PARAM_NICKNAME = 2
    MRIM_CS_WP_REQUEST_PARAM_ONLINE = 9
    MRIM_CS_WP_REQUEST_PARAM_SEX = 5
    MRIM_CS_WP_REQUEST_PARAM_STATUS = 10
    MRIM_CS_WP_REQUEST_PARAM_USER = 0
    MRIM_CS_WP_REQUEST_PARAM_ZODIAC = 12
    MRIM_GET_SESSION_FAIL = 0
    MRIM_GET_SESSION_SUCCESS = 1
    PARAM_VALUE_LENGTH_LIMIT = 64
    PARAMS_NUMBER_LIMIT = 50
    SMS_ACK_DELIVERY_STATUS_INVALID_PARAMS = 0x10000
    SMS_ACK_DELIVERY_STATUS_SUCCESS = 1
    SMS_ACK_SERVICE_UNAVAILABLE = 2
    STATUS_AWAY = 0x02
    STATUS_FLAG_INVISIBLE = 0x80000000
    STATUS_OFFLINE = 0x00
    STATUS_ONLINE = 0x01
    STATUS_OTHER = 0x04
    STATUS_UNDETERMINATED = 0x03

    def __init__(self, logger = None):
        a = lambda x: None
        self.logger=logger if logger else None
        self.error=logger.error if logger else a
        self.info=logger.info if logger else a
        self.debug=logger.debug if logger else a
        self.warn=logger.warn if logger else a
        self.critical=logger.critical if logger else a
        self.inspect = lambda:str(inspect.stack()[0][3])



    def connect(self, port=None, user=None, password=None, type=None):
        self.debug('self.connect: '+ str(locals()))
        #self.proxy = None
        #self.proxy_port = None
        return self.connect_single()

    def disconnect(self):

        self.sock.close()

    def make_packet(self, msg, data=None):

        if data == None:
            dlen = 0
        else:
            dlen = len(data)

        mrim_packet = struct.pack('<11L', self.CS_MAGIC, self.PROTO_VERSION, self.mnumb, msg, dlen, 0, 0, 0, 0, 0, 0)

        if data != None:
            mrim_packet += data

        if self.mnumb == 0xFFFFFFFF:
            self.mnumb = 0
        else:
            self.mnumb += 1

        return mrim_packet

    def get_socket(self, address, port):

        if self.proxy:
            try:
                self.info('Trying to create proxy socket')
                s = socks.socksocket()
                s.setproxy(socks.PROXY_TYPE_HTTP, self.proxy, self.proxy_port)
            except:
                self.info('Faile to create proxy socket')
                s = None
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error as msg:
                s = None

        try:
            print type(address), address
            print type(port), port
            print type((address, port))
            self.info('Trying to connect to %s:%s' % (address, port))
            s.connect((address.encode('cp1251'), port))

        except socket.error as msg:
            self.info('Failed to connect to %s:%s' % (address, port))
            s.close()
            s = None
        return s


    def connect_single(self):

        self.sock = None
        s = self.get_socket(self.server, self.port)
        if s is None:
            return False
        else:
            data = unicode(s.recv(20))
            s.close()
            addr_port = data.split(':')

        s = self.get_socket(addr_port[0], int(addr_port[1]))

        self.mnumb = 0
        s.send(self.make_packet(self.MRIM_CS_HELLO))
        data = s.recv(48)
        hello_ack_list = struct.unpack('<12L', data)
        self.ping_time = hello_ack_list[-1]
        self.sock = s
        return True

    #ToDo: is_connectec
    def is_connected(self):

        return self.sock != None

    def ping(self):
        if not self.is_connected():
            return False

        self.sock.send(self.make_packet(self.MRIM_CS_PING))
        return True

    def pack_data(self, data, encoding="UTF-8"):
        #TODO: check encoding
        #d = bytes(data, encoding)
        d = data.encode(encoding)
        #d = unicode(data, encoding)
        return struct.pack("<L", len(d)) + d

    def set_status(self, status="invisible", xstatus='', xstatus_text=''):
        if not self.is_connected():
            return False
        self.status = status
        self.xstatus = xstatus
        self.xstatus_text = xstatus_text

        status = str.strip(str.lower(status))
        if status == 'invisible':
            status = self.STATUS_ONLINE | self.STATUS_FLAG_INVISIBLE
            status2 = 'STATUS_INVISIBLE'
        elif status == 'online':
            status = self.STATUS_ONLINE
            status2 = 'STATUS_ONLINE'
        elif status == 'away':
            status = self.STATUS_AWAY
            status2 = 'STATUS_AWAY'
        else:
            status2 = status
            status = self.STATUS_OTHER

        data = struct.pack('<L', status) + self.pack_data(status2) + self.pack_data(xstatus,
                                                                                    'UTF-16LE') + self.pack_data(
            xstatus_text, 'UTF-16LE') + struct.pack('<L', 0x03FF)
        self.sock.send(self.make_packet(self.MRIM_CS_CHANGE_STATUS, data))
        return True

    def login(self, login, password):
        self.debug('self.login: ' + str(locals()))
        if not self.is_connected():
            return False
        st = 'STATUS_INVISIBLE'

        if not self.status:
            self.status = 'invisible'

        lang = 'ru'

        login_data = self.pack_data(login) + self.pack_data(password) + struct.pack('<L',
                                                                                    self.STATUS_ONLINE | self.STATUS_FLAG_INVISIBLE) + self.pack_data(
            st) + struct.pack('<3L', 0x00, 0x00, 0x03FF) + self.pack_data(self.user_agent_descr) + self.pack_data(
            lang) + self.pack_data(self.user_agent)
        self.sock.send(self.make_packet(self.MRIM_CS_LOGIN2, login_data))
        data = self.sock.recv(44)
        login_list = struct.unpack('<11L', data)
        msg = login_list[3]

        if msg == self.MRIM_CS_LOGIN_ACK:
            self.sock.send(self.make_packet(self.MRIM_CS_GET_MPOP_SESSION))

            if self.behaviour != 1:
                self.sock.setblocking(0)

            self.email = login
            self.password = password
            return True
        return False

    def read_bytes_from_socket(self, num):
        try:
            data = self.sock.recv(num)
        except:
            return False

        while len(data) < num:
            data += self.sock.recv(num - len(data))
            if not self.is_connected():
                return False
        return data


    def receive_packet(self):
        if not self.is_connected():
            return False

        if self.behaviour == 1:
            self.sock.settimeout(1)

            data = self.read_bytes_from_socket(44)
            if not data:
                return False

            packet_list = struct.unpack('<11L', data)
            dlen = packet_list[4]
            msg = packet_list[3]
            seq = packet_list[2]

            if dlen == 0:
                return [msg, '']

            a = self.read_bytes_from_socket(dlen)
            if not a:
                return False
        else:
            data = self.sock.recv(1)

            if len(data) == 1:
                self.sock.setblocking(1)
                d = self.read_bytes_from_socket(44)
                if not d:
                    return False
                data += d

            if not data:
                return False

            packet_list = struct.unpack('<11L', data)
            dlen = packet_list[4]
            msg = packet_list[3]
            seq = packet_list[2]

            if dlen == 0:
                return [msg, '']

            a = self.read_bytes_from_socket(dlen)

            if not a:
                return False

            self.sock.setblocking(0)
        return [msg, a, seq]
    def is_not_ping(self, packet):
        if not self.is_list(packet):
            return False

        if packet[0] != self.MRIM_CS_MESSAGE_STATUS:
            return False


        self.debug(str(packet))

        return True

    def is_new_ping(self, packet):
        if not self.is_list(packet):
            return False

        if packet[0] != self.MRIM_CS_CONNECTION_PARAMS:
            return False

        ping_list = struct.unpack('<L', packet[1])
        self.ping_time = ping_list[0]
        return True

    def is_list(self, packet):
        return type(packet) == list

    def get_L_from_packet(self, packet):
        data = struct.unpack('<L', packet[1][:4])[0]
        packet[1] = packet[1][4:]
        return data

    def get_bytes_from_packet(self, packet, num):
        data = packet[1][:num]
        packet[1] = packet[1][num:]
        return data

    # некоторые контакты хранятся в win-1251
    def try_encode_in_utf8(self, packet, dlen):
        data = self.get_bytes_from_packet(packet, dlen)
        try:
            #return str(data, 'UTF-8')
            return data.encode('UTF-8')

        except:
            #return str(data, 'windows-1251')
            return data.encode('windows-1251')

    def is_contact_list(self, packet):
        if not self.is_list(packet):
            return False

        if packet[0] != self.MRIM_CS_CONTACT_LIST2:
            return False

        status = self.get_L_from_packet(packet)

        if status == self.GET_CONTACTS_INTERR:
            return 'internal error'
        elif status == self.GET_CONTACTS_ERROR:
            return 'get contacts error'
        elif status != self.GET_CONTACTS_OK:
            return False

        groups = self.get_L_from_packet(packet)
        dlen = self.get_L_from_packet(packet)
        group_mask = self.try_encode_in_utf8(packet, dlen)

        dlen = self.get_L_from_packet(packet)
        contact_mask = self.try_encode_in_utf8(packet, dlen)

        self.groups = groups

        known = []
        unknown = []
        for i in range(groups):
            if group_mask[0] == 'u':
                flag = self.get_L_from_packet(packet)
            else:
                return False

            if group_mask[1] == 's':
                dlen = self.get_L_from_packet(packet)
                #name = str(self.get_bytes_from_packet(packet, dlen), 'UTF-16LE')
                name = self.get_bytes_from_packet(packet, dlen).encode('UTF-16LE')
            else:
                return False

            gr = {}
            gr['name'] = name
            gr['shadow'] = bool(flag & self.CONTACT_FLAG_SHADOW)
            gr['deleted'] = bool(flag & self.CONTACT_FLAG_REMOVED)
            gr['contacts'] = []

            if len(group_mask) > 2:
                for j in range(2, len(group_mask)):
                    if group_mask[j] == 'u':
                        self.get_L_from_packet(packet)
                    elif group_mask[j] == 's':
                        dlen = self.get_L_from_packet(packet)
                        self.get_bytes_from_packet(packet, dlen)
                    else:
                        while self.get_bytes_from_packet(packet, 1) == b'0x00':
                            pass

            known += [gr]
        i = 0

        while len(packet[1]) > 0:
            if contact_mask[0] == 'u':
                flag = self.get_L_from_packet(packet)
            else:
                return False

            if contact_mask[1] == 'u':
                group = self.get_L_from_packet(packet)
            else:
                return False

            if contact_mask[2] == 's':
                dlen = self.get_L_from_packet(packet)
                addr = self.try_encode_in_utf8(packet, dlen)
            else:
                return False

            if contact_mask[3] == 's':
                dlen = self.get_L_from_packet(packet)
                #name = str(self.get_bytes_from_packet(packet, dlen), 'UTF-16LE')
                name = self.get_bytes_from_packet(packet, dlen).encode('UTF-16LE')
            else:
                return False

            if contact_mask[4] == 'u':
                sflags = self.get_L_from_packet(packet)
            else:
                return False

            if contact_mask[5] == 'u':
                status = self.get_L_from_packet(packet)
            else:
                return False

            if contact_mask[6] == 's':
                dlen = self.get_L_from_packet(packet)
                phone = self.try_encode_in_utf8(packet, dlen)
            else:
                return False

            if contact_mask[7] == 's':
                dlen = self.get_L_from_packet(packet)
                status2 = self.try_encode_in_utf8(packet, dlen)
            else:
                return False

            if contact_mask[8] == 's':
                dlen = self.get_L_from_packet(packet)
                #xstatus = str(self.get_bytes_from_packet(packet, dlen), 'UTF-16LE')
                xstatus = self.get_bytes_from_packet(packet, dlen).encode('UTF-16LE')
            else:
                return False

            if contact_mask[9] == 's':
                dlen = self.get_L_from_packet(packet)
                #xstatus_text = str(self.get_bytes_from_packet(packet, dlen), 'UTF-16LE')
                xstatus_text = self.get_bytes_from_packet(packet, dlen).encode('UTF-16LE')
            else:
                return False

            if contact_mask[10] == 'u':
                self.get_L_from_packet(packet)
            else:
                return False

            if contact_mask[11] == 's':
                dlen = self.get_L_from_packet(packet)
                client = self.try_encode_in_utf8(packet, dlen)
            else:
                return False

            if len(contact_mask) > 12:
                for j in range(12, len(contact_mask)):
                    if contact_mask[j] == 'u':
                        self.get_L_from_packet(packet)
                    elif contact_mask[j] == 's':
                        dlen = self.get_L_from_packet(packet)
                        str(self.get_bytes_from_packet(packet, dlen))
                    else:
                        while self.get_bytes_from_packet(packet, 1) == b'0x00':
                            pass

            if status == self.STATUS_OFFLINE:
                status = 'offline'
            elif status == self.STATUS_ONLINE:
                status = 'online'
            elif status == self.STATUS_AWAY:
                status = 'away'
            elif status & self.STATUS_FLAG_INVISIBLE:
                status = 'invisible'
            elif status == self.STATUS_OTHER:
                status = 'other'
            elif status == self.STATUS_UNDETERMINATED:
                status = 'undeterminated'
            else:
                status = 'unknown'

            data = {}
            data['addr'] = addr
            data['name'] = name
            data['status'] = status
            data['phone'] = phone
            data['not-authorized'] = bool(sflags & self.CONTACT_INTFLAG_NOT_AUTHORIZED)
            data['ignore'] = bool(flag & self.CONTACT_FLAG_IGNORE)
            data['invisible'] = bool(flag & self.CONTACT_FLAG_INVISIBLE)
            data['visible'] = bool(flag & self.CONTACT_FLAG_VISIBLE)
            data['shadow'] = bool(flag & self.CONTACT_FLAG_SHADOW)
            data['deleted'] = bool(flag & self.CONTACT_FLAG_REMOVED)
            data['id'] = i + 20
            data['client'] = client
            data['status2'] = status2
            data['xstatus'] = xstatus
            data['xstatus_text'] = xstatus_text

            if len(known) > group:
                known[group]['contacts'] += [data]

            else:
                data['group'] = group
                unknown += [data]
            i += 1
        return [known, unknown]

    def message(self, recipient, text):
        self.debug('self.message' + str(locals()))
        if not self.is_connected():
            return False
        data = struct.pack('<L', 0) +self.pack_data(recipient)+self.pack_data(text, 'UTF-16LE')+self.pack_data(' ')


        self.debug('Data length: '+ str(len(data)))
        self.sock.send(self.make_packet(self.MRIM_CS_MESSAGE, data))
        self.debug('after sending')
        return True


    def sms(self, number, text):
        if not self.is_connected():
            return False

        data = struct.pack('<L', 0) + self.pack_data(number) + self.pack_data(text, 'UTF-16LE')
        self.sock.send(self.make_packet(self.MRIM_CS_SMS, data))
        return True

    def add_contact(self, addr, name,
                    text="Здравствуйте. Пожалуйста, добавьте меня в список ваших контактов. ",
                    phone="", group=0, invisible=False, visible=False, ignore=False, shadow=False, deleted=False,
                    sms=False):
        self.debug(self.inspect() + str(locals()))
        if not self.is_connected():
            return False

        flags = 0

        if invisible:
            flags |= self.CONTACT_FLAG_INVISIBLE
        if visible:
            flags |= self.CONTACT_FLAG_VISIBLE
        if ignore:
            flags |= self.CONTACT_FLAG_IGNORE
        if shadow:
            flags |= self.CONTACT_FLAG_SHADOW
        if deleted:
            flags |= self.CONTACT_FLAG_REMOVED
        if sms:
            flags |= self.CONTACT_FLAG_SMS
            group = 0x67
            addr = 'phone'

        if self.nickname != "":
            nickname = self.nickname
        else:
            nickname = self.email

        txt = base64.b64encode(
            struct.pack('<L', 2) + self.pack_data(nickname, 'UTF-16LE') + self.pack_data(text, 'UTF-16LE'))
        data = struct.pack('<2L', flags, group) + self.pack_data(addr) + self.pack_data(name,
                                                                                        'UTF-16LE') + self.pack_data(
            phone) + struct.pack('<L', len(txt)) + txt + struct.pack('<L', 0)
        self.sock.send(self.make_packet(self.MRIM_CS_ADD_CONTACT, data))
        return True

    def is_add_result(self, packet):
        if not self.is_list(packet):
            return False
        if packet[0] != self.MRIM_CS_ADD_CONTACT_ACK:
            return False

        status = self.get_L_from_packet(packet)
        if status == self.CONTACT_OPER_GROUP_LIMIT:
            return 'group limit'
        elif status == self.CONTACT_OPER_USER_EXISTS:
            return 'user exists'
        elif status == self.CONTACT_OPER_INVALID_INFO:
            return 'invalid info'
        elif status == self.CONTACT_OPER_NO_SUCH_USER:
            return 'no such user'
        elif status == self.CONTACT_OPER_INTERR:
            return 'internal error'
        elif status == self.CONTACT_OPER_ERROR:
            return 'contact operation error'
        elif status != self.CONTACT_OPER_SUCCESS:
            return False
            #id
        return self.get_L_from_packet(packet)

    def is_sms_report(self, packet):
        if not self.is_list(packet):
            return False

        if packet[0] != self.MRIM_CS_SMS_ACK:
            return False

        status = self.get_L_from_packet(packet)

        if status == self.SMS_ACK_DELIVERY_STATUS_INVALID_PARAMS:
            return 'invalid request'

        if status == self.SMS_ACK_SERVICE_UNAVAILABLE:
            return 'service unavailable'

        if status != self.SMS_ACK_DELIVERY_STATUS_SUCCESS:
            return False

        return True


    def is_message(self, packet):

        if not self.is_list(packet):
            return False

        if packet[0] != self.MRIM_CS_MESSAGE_ACK:
            return False

        self.get_bytes_from_packet(packet, 8)
        num = self.get_L_from_packet(packet)
        sender = self.try_encode_in_utf8(packet, num)

        return sender
