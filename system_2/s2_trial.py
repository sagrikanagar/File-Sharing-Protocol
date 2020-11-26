import socket
import os
import stat
import re
import time
import hashlib
import signal
import sys
import subprocess as sub

import numpy as np
# Configure handler for keyboard interrupt


class TimedOutExc(Exception):
    pass


def handler(signum, frame):
    raise TimedOutExc()


signal.signal(signal.SIGALRM, handler)


class System:
    def __init__(self):

        self.server = socket.socket()
        self.client = socket.socket()

        self.HOST = ""
        self.SERVER_PORT = 50000
        self.CLIENT_PORT = 60000

        try:
            self.server.bind((self.HOST, self.SERVER_PORT))
        except:
            self.SERVER_PORT = 50005
            self.server.bind((self.HOST, self.SERVER_PORT))

        self.server.listen(5)

        try:
            self.client.connect((self.HOST, self.CLIENT_PORT))
        except:
            self.CLIENT_PORT = 60005
            self.client.connect((self.HOST, self.CLIENT_PORT))

        self.connection, _ = self.server.accept()
        self.SERVER_DIR = os.path.dirname(os.path.realpath(__file__))
        self.CLIENT_DIR = os.path.dirname(os.path.realpath(__file__))
        self.CACHE_DIR = os.path.join(self.SERVER_DIR, ".cache")

        self.PRE_CHECK_TIME = time.time()
        self.POST_CHECK_TIME = time.time()
        self.TIME = 1
        self.CACHE_SIZE = 151
        self.TIMEOUT = False
        self.run()

    def hash_file(self, filename):
        hash_md5 = hashlib.md5()
        # openfile for reading in binary mode and reading chunks of 4 bytes
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)

        return hash_md5.hexdigest()

    def send_hash(self, sub_dir):
        _, dir_names, filenames = list(
            os.walk(os.path.join(self.SERVER_DIR, sub_dir)))[0]
        for filename in filenames:
            if filename == "s2_trial.py" or filename == "file2.log":
                continue

            self.client.recv(1024)

            hash_value = self.hash_file(os.path.join(
                self.SERVER_DIR, sub_dir, filename))
            st = os.stat(os.path.join(self.SERVER_DIR, sub_dir, filename))
            text = "".join([sub_dir, "/", filename, ";",
                            hash_value, ";", str(st.st_mtime)])
            # hash_value = self.hash_file(self.SERVER_DIR + sub_dir + "/" + filename)
            # st = os.stat(self.SERVER_DIR + sub_dir + "/"+ filename)
            # text = sub_dir + "/" + filename + ';' + hash_value + ';' + str(st.st_mtime)

            self.client.send(text)

        for dir_name in dir_names:
            self.send_hash(os.path.join(sub_dir, dir_name))
            # self.send_hash(sub_dir + "/" + dir_name)
        return

    def download_file(self, message):
        messages = message.split(" ")
        path = self.SERVER_DIR + messages[1]
        path2 = self.CLIENT_DIR + messages[1]
        self.client.send("1 "+path2)
        value = self.client.recv(1024)
        values = value.split(";")
        hash1 = values[0]
        mode = int(values[1])
        if os.path.exists(path):
            hash2 = self.hash_file(path)
            os.chmod(path, mode & 0o777)
            if hash1 == hash2:
                self.client.send("No Need")
            else:
                self.client.send("send")
                flag = 0
                val = self.client.recv(1024)
                if val == "True":
                    if os.access(path, os.W_OK):
                        self.client.send("True")
                    else:
                        self.client.send("False")
                        flag = 1
                else:
                    self.client.send("False")
                    flag = 1

                if flag == 1:
                    print("PERMISSION DENIED")
                    return
                print(messages[1], "UPDATED")
                f = open(path, 'wb')
                while True:
                    data = self.client.recv(1024)
                    self.client.send("OK")
                    if data == "File Finished":
                        break
                    else:
                        f.write(data)
                f.close()
        else:
            self.client.send("send")
            flag = 0
            val = self.client.recv(1024)
            if val == "True":
                self.client.send("True")
                flag = 0
            else:
                self.client.send("False")
                flag = 1

            if flag == 1:
                print("PERMISSION DENIED")
                return
            print(messages[1], "UPDATED")
            f = open(path, 'wb')
            while True:
                data = self.client.recv(1024)
                self.client.send("OK")
                if data == "File Finished":
                    break
                else:
                    f.write(data)
            f.close()
            os.chmod(path, mode & 0o777)

        return

    def update_sharedfolders_r(self):
        while True:
            message = self.client.recv(1024)
            messages = message.split(" ")

            if message == "Over":
                self.client.send("OK")
                break

            if messages[0] == "1":
                if messages[1] == "/s1_trial.py" or messages[1] == "/file1.log":
                    self.client.send("yes")
                    continue
                self.download_file(message)
            elif messages[0] == "2":
                path = self.SERVER_DIR + messages[1]
                if not os.path.exists(path):
                    os.makedirs(path)
                    self.client.send("no")
                else:
                    self.client.send("yes")

        return

    def share_file(self, filename):

        f = open(filename, "rb")
        chunk = f.read(1024)
        while(chunk):
            self.connection.send(chunk)
            self.connection.recv(1024)
            chunk = f.read(1024)

        f.close()
        self.connection.send("File Finished")
        self.connection.recv(1024)
        return

    def update_shared_dirs(self, sub_dir):
        dir_path, dir_names, filenames = list(
            os.walk(os.path.join(self.SERVER_DIR, sub_dir)))[0]

        for filename in filenames:
            self.connection.send("".join(["1", " ", sub_dir, "/", filename]))
            response = self.connection.recv(1024)
            path = response.split()

            if path[0] == "1":
                hash_value = self.hash_file(path[1])
                stat = os.stat(path[1])
                text = "".join([hash_value, ";", str(stat.st_mode)])
                self.connection.send(text)
                response = self.connection.recv(1024)

            if response == "send":
                flag = False

                # if os.access(dir_path+'/'+filename,os.R_OK):
                if os.access(dir_path+'/'+filename, os.R_OK):
                    self.connection.send("True")
                    val = self.connection.recv(1024)

                    if val == "True":
                        flag = False
                    else:
                        flag = True
                else:
                    self.connection.send("False")
                    flag = True
                    self.connection.recv(1024)

                if flag is True:
                    continue

                self.share_file(os.path.join(dir_path, filename))

        for dir_name in dir_names:
            if dir_name[0] == ".":
                continue
            self.connection.send("".join(["2", " ", sub_dir, "/", dir_name]))
            self.connection.recv(1024)
            self.update_shared_dirs(os.path.join(sub_dir, dir_name))
        return

    def run(self):
        self.CLIENT_DIR = self.client.recv(1024)
        self.client.send("OK")

        self.connection.send(self.SERVER_DIR)
        self.connection.recv(1024)

        self.update_sharedfolders_r()
        self.PRE_CHECK_TIME = time.time()

        f = open(self.SERVER_DIR + "/" + "file2.log", "a+")
        f.write("AUTO UPDATE" + "   " + time.ctime(time.time()) + "\n")
        f.close()

        self.update_shared_dirs("")
        self.connection.send("Over")
        self.connection.recv(1024)
        self.POST_CHECK_TIME = time.time()

        while True:
            if time.time() - self.PRE_CHECK_TIME >= 600:
                self.update_sharedfolders_r()
                self.PRE_CHECK_TIME = time.time()
                f = open(self.SERVER_DIR+"/"+"file2.log", "a+")
                f.write("AUTO UPDATE"+"   "+time.ctime(time.time())+"\n")
                f.close()
                self.update_shared_dirs("")
                self.connection.send("Over")
                self.connection.recv(1024)
                self.POST_CHECK_TIME = time.time()
                continue

            message = self.client.recv(1024)
            if message == "NO INPUT":
                self.client.send("OK")
            else:
                self.client.send("ok")
                f = open(self.SERVER_DIR+"/"+"file2.log", "a+")
                f.write(message+"   "+time.ctime(time.time())+"\n")
                f.close()
                messages = message.split(" ")
                length2 = len(messages)
                if messages[0] == "close":
                    break
                elif messages[0] == "IndexGet":
                    if length2 == 1:
                        continue
                    if messages[1] == "longlist" or messages[1] == "shortlist":
                        p = sub.Popen(['ls'], stdout=sub.PIPE, stderr=sub.PIPE)
                        output, errors = p.communicate()
                        output = output + "Over"
                        lines = output.split("\n")
                        count = 0
                        for line in lines:
                            if line != "Over" and line != "s2_trial.py" and line != "file2.log":
                                if messages[1] == "longlist" and length2 == 3:
                                    word = messages[2]
                                    flag = False
                                    f = open(os.path.join(
                                        self.SERVER_DIR, line))
                                    content = f.read()
                                    if content.find(word) != -1 and line[-4:] == ".txt":
                                        flag = True
                                    f.close()

                                    if flag is False:
                                        continue

                                if messages[1] == "shortlist" and length2 == 5:
                                    if messages[4][0] == "*" and messages[4][1:] == ".txt":
                                        if line[-4:] != ".txt":
                                            continue
                                    elif messages[4][0] == "*" and messages[4][1:] == ".pdf":
                                        if line[-4:] != ".pdf":
                                            continue

                                st = os.stat(self.SERVER_DIR+'/'+line)
                                line = line + ';' + \
                                    str(st.st_size) + ';' + \
                                    str(st.st_mode) + ';' + \
                                    str(st.st_mtime)
                                self.client.recv(1024)
                                self.client.send(line)
                                if messages[1] == "shortlist" and length2 < 4:
                                    break

                            elif line == "Over":
                                self.client.recv(1024)
                                self.client.send(line)
                elif messages[0] == "FileHash":
                    if length2 == 1:
                        continue
                    if messages[1] == "verify":
                        if length2 == 2:
                            continue
                        self.client.recv(1024)
                        filename = messages[2]
                        if os.path.exists(self.SERVER_DIR+'/'+filename):
                            st = os.stat(self.SERVER_DIR+'/'+filename)
                            hash_value = self.hash_file(
                                self.SERVER_DIR+'/'+filename)
                            self.client.send(hash_value+';'+str(st.st_mtime))
                        else:
                            self.client.send("FALSE")

                    if messages[1] == "checkall":
                        self.send_hash("")
                        self.client.recv(1024)
                        self.client.send("Over")
                elif messages[0] == "FileDownload":
                    if length2 == 1:
                        continue
                    if messages[1] == "TCP":
                        if length2 == 2:
                            continue
                        filename = messages[2]
                        if os.path.exists(self.SERVER_DIR + '/' + filename):
                            self.client.recv(1024)
                            self.client.send("OK")

                            self.client.recv(1024)
                            hash_value = self.hash_file(
                                self.SERVER_DIR + '/' + filename)
                            st = os.stat(self.SERVER_DIR + '/' + filename)
                            text = hash_value + ';' + \
                                str(st.st_size) + ';' + \
                                str(st.st_mtime) + ';' + str(st.st_mode)
                            self.client.send(text)

                            mess = self.client.recv(1024)
                            self.client.send("OK")
                            if mess == "SEND":
                                f = open(self.SERVER_DIR +
                                         '/' + filename, 'rb')
                                l = f.read(1024)
                                while(l):
                                    self.client.recv(1024)
                                    self.client.send(l)
                                    l = f.read(1024)
                                self.client.recv(1024)
                                self.client.send("Over")

                        else:
                            self.client.recv(1024)
                            self.client.send("FALSE")
                    if messages[1] == "UDP":
                        if length2 == 2:
                            continue
                        filename = messages[2]
                        if os.path.exists(self.SERVER_DIR + '/' + filename):
                            self.client.recv(1024)
                            self.client.send("OK")

                            self.client.recv(1024)
                            hash_value = self.hash_file(
                                self.SERVER_DIR + '/' + filename)
                            st = os.stat(self.SERVER_DIR + '/' + filename)
                            text = hash_value + ';' + \
                                str(st.st_size) + ';' + \
                                str(st.st_mtime) + ';' + str(st.st_mode)
                            self.client.send(text)

                            mess = self.client.recv(1024)
                            self.client.send("OK")
                            if mess == "SEND":
                                clientSocket = socket.socket(
                                    socket.AF_INET, socket.SOCK_DGRAM)
                                f = open(self.SERVER_DIR+'/'+filename, 'rb')
                                l = f.read(1024)
                                while(l):
                                    clientSocket.sendto(l, (self.HOST, 60002))
                                    l = f.read(1024)
                                clientSocket.sendto("Over", (self.HOST, 60002))
                                clientSocket.close()
                        else:
                            self.client.recv(1024)
                            self.client.send("FALSE")
                elif messages[0] == "Cache":
                    if length2 == 1:
                        continue
                    if messages[1] == "verify":
                        if length2 == 2:
                            continue

                        filename = messages[2]
                        requirement = self.client.recv(1024)
                        self.client.send("OK")

                        if requirement == "NO NEED":
                            pass
                        elif os.path.exists(self.SERVER_DIR + '/' + filename):

                            self.client.recv(1024)
                            self.client.send("OK")

                            self.client.recv(1024)
                            hash_value = self.hash_file(
                                self.SERVER_DIR + '/' + filename)
                            st = os.stat(self.SERVER_DIR + '/' + filename)
                            text = hash_value + ';' + \
                                str(st.st_size) + ';' + \
                                str(st.st_mtime) + ';' + str(st.st_mode)
                            self.client.send(text)

                            mess = self.client.recv(1024)
                            self.client.send("OK")
                            if mess == "SEND":
                                clientSocket = socket.socket(
                                    socket.AF_INET, socket.SOCK_DGRAM)
                                f = open(self.SERVER_DIR+'/'+filename, 'rb')
                                l = f.read(1024)
                                while(l):
                                    clientSocket.sendto(l, (self.HOST, 60002))
                                    l = f.read(1024)
                                clientSocket.sendto("Over", (self.HOST, 60002))
                                clientSocket.close()
                        else:
                            self.client.recv(1024)
                            self.client.send("FALSE")

            signal.alarm(self.TIME)

            try:
                if self.TIMEOUT is False:
                    command = raw_input("$> ")
                else:
                    self.TIMEOUT = False
                    command = raw_input()
                signal.alarm(0)
                self.connection.send(command)
                self.connection.recv(1024)
                commands = command.split(" ")
                length = len(commands)
                if commands[0] == "close":
                    break
                elif commands[0] == "IndexGet":
                    if length == 1:
                        print("INVALID COMMAND")
                        continue
                    if commands[1] == "longlist" or commands[1] == "shortlist":
                        while True:
                            self.connection.send("OK")
                            l = self.connection.recv(1024)
                            if l == "Over":
                                break
                            else:
                                ls = l.split(";")
                                size = int(ls[1])
                                mode = int(ls[2])
                                mtime = float(ls[3])
                                if stat.S_ISREG(mode):
                                    file = "REG_FILE"
                                elif stat.S_ISDIR(mode):
                                    file = "DIRECTORY"
                                elif stat.S_ISLNK(mode):
                                    file = "SYM_LINK"
                                elif stat.S_ISSOCK(mode):
                                    file = "SOCKET"
                                else:
                                    file = "OTHERS"
                                if commands[1] == "longlist":
                                    print(
                                        "FILE-", ls[0], ", SIZE-", size, ", TYPE-", file, ", TIMESTAMP-", time.ctime(mtime))

                                elif commands[1] == "shortlist":
                                    if length < 4:
                                        print("INVALID COMMAND")
                                        break
                                    time1 = float(commands[2])
                                    time2 = float(commands[3])
                                    if time1 <= mtime and mtime <= time2:
                                        print(
                                            "FILE-", ls[0], ", SIZE-", size, ", TYPE-", file, ", TIMESTAMP-", time.ctime(mtime))

                                else:
                                    if length < 3:
                                        print("INVALID COMMAND")
                                        break
                                    string = commands[2]
                                    if re.search(string, ls[0]):
                                        print(
                                            "FILE-", ls[0], ", SIZE-", size, ", TYPE-", file, ", TIMESTAMP-", time.ctime(mtime))
                elif commands[0] == "FileHash":
                    if length == 1:
                        print("INVALID COMMAND")
                        continue
                    if commands[1] == "verify":
                        if length == 2:
                            print("INVALID COMMAND")
                            continue
                        filename = commands[2]
                        self.connection.send("OK")
                        value = self.connection.recv(1024)

                        if value == "FALSE":
                            print("IMPROPER FILENAME")
                        else:
                            values = value.split(";")
                            hash_value = values[0]
                            mtime = float(values[1])
                            if os.path.exists(self.SERVER_DIR+'/'+filename):
                                hash_value2 = self.hash_file(
                                    self.SERVER_DIR+'/'+filename)
                                if hash_value == hash_value2:
                                    print("NOT UPDATED", hash_value,
                                          "TIMESTAMP:", time.ctime(mtime))
                                else:
                                    print("UPDATED", hash_value,
                                          "TIMESTAMP:", time.ctime(mtime))

                            else:
                                print("FILE DOESN'T EXIST IN THIS FOLDER",
                                      hash_value, time.ctime(mtime))

                    elif commands[1] == "checkall":
                        while True:
                            self.connection.send("Ok")
                            value = self.connection.recv(1024)
                            if value == "Over":
                                break
                            else:
                                values = value.split(";")
                                hash_value = values[1]
                                filename = values[0]
                                mtime = float(values[2])
                                if os.path.exists(self.SERVER_DIR + filename):
                                    hash_value2 = self.hash_file(
                                        self.SERVER_DIR + filename)
                                    if hash_value == hash_value2:
                                        print("NOT UPDATED", filename,
                                              hash_value, time.ctime(mtime))
                                    else:
                                        print("UPDATED", filename,
                                              hash_value, time.ctime(mtime))
                                else:
                                    print("FILE NOT THERE IN THIS FOLDER",
                                          filename, hash_value, time.ctime(mtime))

                    else:
                        print("INVALID COMMAND")
                elif commands[0] == "FileDownload":
                    if length == 1:
                        print("INVALID COMMAND")
                        continue
                    if commands[1] == "TCP":
                        if length == 2:
                            print("INVALID COMMAND")
                            continue
                        filename = commands[2]
                        self.connection.send("OK")
                        mess = self.connection.recv(1024)
                        if mess == "FALSE":
                            print("IMPROPER FILENAME")
                        else:
                            self.connection.send("OK")
                            value = self.connection.recv(1024)
                            values = value.split(";")
                            hash_value = values[0]
                            size = int(values[1])
                            mtime = float(values[2])
                            mode = int(values[3])

                            if os.path.exists(self.SERVER_DIR + '/' + filename):
                                os.chmod(self.SERVER_DIR + '/' +
                                         filename, mode & 0o777)
                                hash_value2 = self.hash_file(
                                    self.SERVER_DIR + '/' + filename)
                                if hash_value == hash_value2:
                                    self.connection.send("NO NEED")
                                    self.connection.recv(1024)
                                    print("FILE ALREADY UPDATED")
                                    print(filename, size, time.ctime(
                                        mtime), hash_value)
                                else:
                                    self.connection.send("SEND")
                                    self.connection.recv(1024)
                                    f = open(self.SERVER_DIR +
                                             '/' + filename, 'wb')
                                    while True:
                                        self.connection.send("OK")
                                        data = self.connection.recv(1024)
                                        if data == "Over":
                                            break
                                        else:
                                            f.write(data)
                                    f.close()
                                    hash_value2 = self.hash_file(
                                        self.SERVER_DIR + '/' + filename)
                                    if hash_value == hash_value2:
                                        print("HASH CHECKED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)
                                    else:
                                        print("HASH FAILED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)

                            else:
                                self.connection.send("SEND")
                                self.connection.recv(1024)
                                f = open(self.SERVER_DIR +
                                         '/' + filename, 'wb')
                                while True:
                                    self.connection.send("OK")
                                    data = self.connection.recv(1024)
                                    if data == "Over":
                                        break
                                    else:
                                        f.write(data)
                                f.close()
                                os.chmod(self.SERVER_DIR + '/' +
                                         filename, mode & 0o777)
                                hash_value2 = self.hash_file(
                                    self.SERVER_DIR + '/' + filename)
                                if hash_value == hash_value2:
                                    print("HASH CHECKED")
                                    print(filename, size, time.ctime(
                                        mtime), hash_value)
                                else:
                                    print("HASH FAILED")
                                    print(filename, size, time.ctime(
                                        mtime), hash_value)

                    elif commands[1] == "UDP":
                        if length == 2:
                            print("INVALID COMMAND")
                            continue
                        filename = commands[2]
                        self.connection.send("OK")
                        mess = self.connection.recv(1024)
                        if mess == "FALSE":
                            print("IMPROPER FILENAME")
                        else:
                            self.connection.send("OK")
                            value = self.connection.recv(1024)
                            values = value.split(";")
                            hash_value = values[0]
                            size = int(values[1])
                            mtime = float(values[2])
                            mode = int(values[3])

                            if os.path.exists(self.SERVER_DIR + '/' + filename):
                                os.chmod(self.SERVER_DIR + '/' +
                                         filename, mode & 0o777)
                                hash_value2 = self.hash_file(
                                    self.SERVER_DIR + '/' + filename)
                                if hash_value == hash_value2:
                                    self.connection.send("NO NEED")
                                    self.connection.recv(1024)
                                    print("FILE ALREADY UPDATED")
                                    print(filename, size, time.ctime(
                                        mtime), hash_value)
                                else:
                                    self.connection.send("SEND")
                                    self.connection.recv(1024)

                                    sock1 = socket.socket(
                                        socket.AF_INET, socket.SOCK_DGRAM)
                                    sock1.bind((self.HOST, 60002))
                                    f = open(self.SERVER_DIR +
                                             '/' + filename, 'wb')
                                    while 1:
                                        data, clientAddress = sock1.recvfrom(
                                            1024)
                                        if data == "Over":
                                            break
                                        else:
                                            f.write(data)
                                    f.close()
                                    sock1.close()
                                    hash_value2 = self.hash_file(
                                        self.SERVER_DIR + '/' + filename)
                                    if hash_value == hash_value2:
                                        print("HASH CHECKED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)
                                    else:
                                        print("HASH FAILED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)

                            else:
                                self.connection.send("SEND")
                                self.connection.recv(1024)
                                sock1 = socket.socket(
                                    socket.AF_INET, socket.SOCK_DGRAM)
                                sock1.bind((self.HOST, 60002))
                                f = open(self.SERVER_DIR +
                                         '/' + filename, 'wb')
                                while 1:
                                    data, clientAddress = sock1.recvfrom(1024)
                                    if data == "Over":
                                        break
                                    else:
                                        f.write(data)
                                f.close()
                                sock1.close()
                                os.chmod(self.SERVER_DIR + '/' +
                                         filename, mode & 0o777)
                                hash_value2 = self.hash_file(
                                    self.SERVER_DIR + '/' + filename)
                                if hash_value == hash_value2:
                                    print("HASH CHECKED")
                                    print(filename, size, time.ctime(
                                        mtime), hash_value)
                                else:
                                    print("HASH FAILED")
                                    print(filename, size, time.ctime(
                                        mtime), hash_value)

                    else:
                        print("INVALID COMMAND")

                elif commands[0] == "Cache":
                    if length == 1:
                        print("INVALID COMMAND")
                        continue

                    if commands[1] == "verify":
                        if length == 2:
                            print("INVALID COMMAND")
                            continue
                        filename = commands[2]

                        if not os.path.exists(self.CACHE_DIR):
                            os.makedirs(self.CACHE_DIR)

                        if os.path.exists(os.path.join(self.CACHE_DIR, filename)):
                            self.connection.send("NO NEED")
                            self.connection.recv(1024)
                            print(filename, os.path.getsize(
                                os.path.join(self.CACHE_DIR, filename)))
                        else:
                            self.connection.send("SEND")
                            self.connection.recv(1024)

                            self.connection.send("OK")
                            mess = self.connection.recv(1024)
                            if mess == "FALSE":
                                print("IMPROPER FILENAME")
                            else:
                                self.connection.send("OK")
                                value = self.connection.recv(1024)
                                values = value.split(";")
                                hash_value = values[0]
                                size = int(values[1])
                                mtime = float(values[2])
                                mode = int(values[3])

                                _, _, filenames = list(
                                    os.walk(self.CACHE_DIR))[0]

                                sizes = [int(os.path.getsize(os.path.join(
                                    self.CACHE_DIR, name))) for name in filenames]
                                mtimes_sorted = np.argsort([float(os.path.getmtime(
                                    os.path.join(self.CACHE_DIR, name))) for name in filenames]).tolist()

                                while np.sum(sizes) + size > self.CACHE_SIZE and len(mtimes_sorted) > 0:
                                    os.remove(os.path.join(
                                        self.CACHE_DIR, filenames[mtimes_sorted[0]]))
                                    sizes.pop(mtimes_sorted[0])
                                    filenames.pop(mtimes_sorted[0])
                                    mtimes_sorted.pop(0)

                                if os.path.exists(self.CACHE_DIR + "/" + filename):
                                    os.chmod(self.CACHE_DIR + "/" +
                                             filename, mode & 0o777)
                                    hash_value2 = self.hash_file(
                                        self.CACHE_DIR + "/" + filename
                                    )
                                    if hash_value == hash_value2:
                                        self.connection.send("NO NEED")
                                        self.connection.recv(1024)
                                        print("FILE ALREADY UPDATED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)
                                    else:
                                        self.connection.send("SEND")
                                        self.connection.recv(1024)

                                        sock1 = socket.socket(
                                            socket.AF_INET, socket.SOCK_DGRAM
                                        )
                                        sock1.bind((self.HOST, 60002))
                                        f = open(self.CACHE_DIR +
                                                 "/" + filename, "wb")
                                        while 1:
                                            data, clientAddress = sock1.recvfrom(
                                                1024)
                                            if data == "Over":
                                                break
                                            else:
                                                f.write(data)
                                        f.close()
                                        sock1.close()

                                        hash_value2 = self.hash_file(
                                            self.CACHE_DIR + "/" + filename)

                                        if hash_value == hash_value2:
                                            print("HASH CHECKED")
                                            print(
                                                filename,
                                                size,
                                                time.ctime(mtime),
                                                hash_value,
                                            )
                                        else:
                                            print("HASH FAILED")
                                            print(
                                                filename,
                                                size,
                                                time.ctime(mtime),
                                                hash_value,
                                            )

                                    print(filename, size)
                                else:
                                    self.connection.send("SEND")
                                    self.connection.recv(1024)
                                    sock1 = socket.socket(
                                        socket.AF_INET, socket.SOCK_DGRAM)
                                    sock1.bind((self.HOST, 60002))
                                    f = open(self.CACHE_DIR +
                                             "/" + filename, "wb")
                                    while 1:
                                        data, clientAddress = sock1.recvfrom(
                                            1024)
                                        if data == "Over":
                                            break
                                        else:
                                            f.write(data)
                                    f.close()
                                    sock1.close()
                                    os.chmod(self.CACHE_DIR + "/" +
                                             filename, mode & 0o777)

                                    hash_value2 = self.hash_file(
                                        self.CACHE_DIR + "/" + filename
                                    )
                                    if hash_value == hash_value2:
                                        print("HASH CHECKED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)
                                    else:
                                        print("HASH FAILED")
                                        print(filename, size, time.ctime(
                                            mtime), hash_value)
                                    print(filename, size)

                    elif commands[1] == "show":
                        if not os.path.exists(self.CACHE_DIR):
                            os.makedirs(self.CACHE_DIR)

                        _, _, filenames = list(os.walk(self.CACHE_DIR))[0]
                        for name in filenames:
                            print(name, os.path.getsize(
                                os.path.join(self.CACHE_DIR, name)))
                        # Step 1: Read all files in the Cache directory, and display their filename and size
                else:
                    print("INVALID COMMAND")
            except TimedOutExc:
                signal.alarm(0)
                self.TIMEOUT = True
                self.connection.send("NO INPUT")
                self.connection.recv(1024)


system = System()
