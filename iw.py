# -*- coding: utf8 -*-
"""Возможный вариант использования утилиты"""

import sender
from logger import mrim_logger
from store import logins, passes

message_recipient = u'email@mail.ru'
sms_recipient = u'79037923722'
message = u'Give me all your money!'

if __name__=='__main__':
    s = sender.Sender(logins, passes, logger=mrim_logger())
    s.send_message(message_recipient, message)
    s.send_sms(sms_recipient, message)
