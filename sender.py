# -*- coding: iso-8859-15 -*-
import sys
import mrim
import time
import threading
import os
import pickle
import logging
import traceback
from store import *


class Sender:
    base_path = os.path.abspath(os.path.dirname(__file__))

    send_interval = 62            # чуть больше чем 1 минуту
    day_interval = 86401          # чуть больше чем 1 сутки
    max_acsii_message_len = 139   # максимальный размер ascii - сообщения
    login_num = None              # номер последнего использованного логина
    wait_confirm_interval = 8.0
    wait_add_interval = 9.0

    unable_to_send = []
    lock_time = []
    result = ""

    def __init__(self, logins, passes, logger = None):
        self.logins = logins
        self.passes = passes
        self.log_filename = log_filename
        self.logger = logger
        self.initLogger(logger)

    def initLogger(self, logger = None):
        os.environ['LANG'] = 'ru_RU.UTF-8'

        if not logger:
            logging.basicConfig(level=logging.DEBUG,
                                format='%(asctime)-18s %(levelname)-13s %(message)s',
                                datefmt='%y-%m-%d %H:%M:%S',
                                filename=self.log_filename)
            self.logger = logging.getLogger('mrim')


    def read_login_num(self):
        try:
            with open(self.base_path + "/lastloginnum.dat", 'rb') as f:
                t = pickle.load(f)
                self.login_num = t[0]
                print t[0]
                self.lock_time = pickle.load(f)
                self.unable_to_send = pickle.load(f)

        except:
            self.login_num = 0
            self.unable_to_send = []
            self.lock_time = []

            for i in self.logins:
                self.lock_time.append(0)
                self.unable_to_send.append(False)

        # количество логинов не соответствует данным в файле
        if len(self.logins) != len(self.lock_time):
            self.unable_to_send = []
            self.lock_time = []

            self.login_num = 0
            for i in self.logins:
                self.lock_time.append(0)
                self.unable_to_send.append(False)

    def write_login_num(self):
        try:
            with open(self.base_path + "/lastloginnum.dat", 'wb') as f:
                pickle.dump([self.login_num], f)
                pickle.dump(self.lock_time, f)
                pickle.dump(self.unable_to_send, f)

        except:
            t_str = "Unable to write login data to file " + self.base_path + "/lastloginnum.dat"
            self.result += t_str + "\n"
            self.logger.critical(t_str)

    def is_in_contact_list(self, list, phone):
        for group in list[0]:
            for contact in group['contacts']:
                if contact['phone'] == phone:
                    return True

        #unknown contacts
        for contact in list[1]:
            if contact['phone'] == phone:
                return True

        return False

    def update_unable_to_send(self):
        list = []
        for x in self.lock_time:
            list.append(x > time.time())
        self.unable_to_send = list

    def sms_timeout(self, send):
        send[0] = True

    def send_message(self, recipient, message):
        self.read_login_num()
        agent = mrim.Mrim(logger = self.logger)
        if not agent.connect():
            self.logger.error('Failed to connect')
            return False
        if not agent.login(self.logins[self.login_num], self.passes[self.login_num]):
            self.logger.error('Failed to connect')
        agent.ping()
        self.logger.info('Settings status to Online')
        agent.set_status("online")
        t=time.time()
        packets_num = 0
        can_send = False
        message_sent=False
        while packets_num<500:
            packets_num+=1
            if time.time() >= (t+agent.ping_time):
                agent.ping()
                t = time.time()
            packet = agent.receive_packet()
            agent.is_new_ping(packet)
            if agent.is_contact_list(packet):
                self.logger.info('Recieved contact list')
                can_send = True

            if can_send and not message_sent:
                mes = agent.message(recipient, message)
                self.logger.debug('Sent: '+str(mes))
                message_sent = True

            if message_sent:

                if agent.is_not_ping(packet):
                    self.logger.info('Recieved message status')
                    return False


            #Действия
            time.sleep(0.5e-3)



    def send_sms_part(self, phone, message):
        agent = mrim.Mrim(logger=self.logger)
        if not agent.connect():
            t_str = "Unable to connect to " + agent.server
            self.logger.error(t_str)
            self.result += t_str + "\n"
            return False

        if not agent.login(self.logins[self.login_num], self.passes[self.login_num]):
            t_str = "Unable to login to " + self.logins[self.login_num]
            self.logger.error(t_str)
            self.result += t_str + "\n"
            return False

        self.logger.info("Email: " + self.logins[
            self.login_num] + ". Attempting to send sms to +" + phone + " with text: \"" + message + "\".")
        agent.ping()
        agent.set_status("online")
        t = time.time()

        send = [False]                                  # по ссылке передаются списки и прочее, примитивы не передаются
        i = 0                                           #количество полученных пакетов. На случай если что-то пойдет не так, скрипт выйдет после 500 полученных пакетов
        while (not send[0]) and (i < 500):             #пока не вылетели и не отправили сообщение
            i += 1                                        #получен пакет
            # Удержание соединения с сервером
            if time.time() >= (t + agent.ping_time):
                self.logger.info("Ping")
                agent.ping()
                t = time.time()

            packet = agent.receive_packet()
            agent.is_new_ping(packet)

            #Действия
            list = agent.is_contact_list(packet)
            if list:                                      #если прислали контакт лист
                if self.is_in_contact_list(list, phone):   #контакт найден в списке, отправляем смску
                    self.logger.info("Contact found")
                    self.logger.info("Sending sms")
                    agent.sms('+' + phone, message)
                else:                                       #не найден, добавляем
                    self.logger.info("Contact NOT found")
                    self.logger.info("Sleeping...")
                    time.sleep(self.wait_add_interval)
                    self.logger.info("Adding contact +" + phone)
                    agent.add_contact("phone", phone, "text O.o", phone, 1000003, False, False, False, False, False,
                                      True) # - добавить контакт в список. bool флаги говорят за себя. text - сообщение запроса авторизации. По умолчанию равно стандартному.

            list = agent.is_add_result(packet)            #если прислали результат добавления контакта
            if type(list) == int:                         # то отправляем смс, проверяя чтобы пришла либо цифра либо true
                self.logger.info("Sending sms")
                agent.sms('+' + phone, message)
            elif type(list) != bool:
                self.logger.error(list)

            list = agent.is_sms_report(packet)            # еcли пришел пакет с подтверждение попытки отправки
            if list:                                      # то ждем
                sms_t = threading.Timer(self.wait_confirm_interval, self.sms_timeout, [send])
                sms_t.start()

            list = agent.is_message(packet)                # если прислали ответ, что превышен лимит собщений
            if list == phone:                              # то выходим
                self.lock_time[self.login_num] = time.time() + self.day_interval
                t_str = "Sms limit exceeded at email " + self.logins[self.login_num]
                self.result += t_str + ".\n"
                self.logger.error(t_str)
                sms_t.cancel()
                break

            #чтобы не повесить сервер
            time.sleep(0.5e-3)

        agent.disconnect()

        if send[0]:
            return True

        else:
            #если за 500 пакетов ничего не произошло, то выходим. Пишем ошибку, но на всякий пожарный пытаемся отправить, попытка, как говорится не пытка.
            if i > 500:
                t_str = "contact list not send. Sms send Error."
                self.result += t_str + "\n"
                self.logger.error(t_str)
            return False

    def is_unable_to_send(self):
        for x in self.unable_to_send:
            if not x:
                return False
        return True

    def is_utf(self, t_str):
        #return len(t_str) != len(bytes(t_str, 'UTF-8'))
        return len(t_str) != len(t_str.encode('UTF-8'))
        #return len(t_str) != len(unicode(t_str,'UTF-8'))


    def send_sms(self, phone, message):
        try:
            self.logger.info("Attempting to send sms to +" + phone + " with text: \"" + message + "\".")
            self.read_login_num()

            # проверим доступна ли посылка смс
            self.update_unable_to_send()
            if self.is_unable_to_send():
                t_str = "Sms send error: sms limit exceeded at all emails."
                self.result += t_str
                self.logger.critical(t_str)

                return self.result

            message_num = 1
            while len(message) != 0:
                if time.time() > self.lock_time[self.login_num]:
                    # +1 из-за пробела после email
                    login_len = len(self.logins[self.login_num]) + 1
                    text_len = self.max_acsii_message_len
                    sms_len = self.max_acsii_message_len
                    number_str = ""

                    # если не умещается в одно сообщение
                    if (len(message) > (int(text_len / (1 + self.is_utf(message))) - login_len)) or (message_num != 1):
                        number_str = '[' + str(message_num) + ']'

                    temp_message = number_str + message
                    # определение максимальной длины сообщения
                    if self.is_utf(temp_message[:text_len - login_len]):
                        text_len = int(text_len / 2) - login_len

                        if not self.is_utf(temp_message[:text_len]):
                            sms_len = self.max_acsii_message_len - login_len

                            for x in temp_message[text_len:sms_len]:
                                if self.is_utf(x):
                                    break

                                text_len += 1
                    else:
                        text_len -= login_len
                        sms_len -= login_len

                    # дополняем пробелами
                    if len(temp_message) < sms_len:
                        temp_message = temp_message[:text_len] + ' ' * (sms_len - len(temp_message))

                    if self.send_sms_part(phone, temp_message[:text_len]):
                        message_num += 1
                        self.lock_time[self.login_num] = time.time() + self.send_interval
                        message = message[text_len - len(number_str):]

                    else:
                        self.unable_to_send[self.login_num] = True

                time.sleep(0.5)

                if self.login_num >= (len(self.logins) - 1):
                    self.login_num = 0

                else:
                    self.login_num += 1

                if self.is_unable_to_send():
                    t_str = "Sms send error: sms limit exceeded at all emails."
                    self.result += t_str
                    self.logger.critical(t_str)
                    break

            else:
                t_str = "Sms sent"
                self.result += t_str
                self.logger.info(t_str)

            self.write_login_num()
        except:
            exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
            self.logger.critical(''.join(traceback.format_exception(exceptionType, exceptionValue, exceptionTraceback)))
            self.result = "Critical error. See log file."
        return self.result
