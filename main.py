# Wei
from socket import *
import threading
from datetime import datetime
import os
import ssl
# Wen
from add import *
from modify import *
from show_bulletin import *
import urllib.parse

# Wei
HOST = "127.0.0.1"
#HTTP_PORT = int(os.getenv("HTTP_PORT"))
HTTP_PORT = 9487
HTTPS_PORT = 8787
USE_HTTPS = True

# Wen
users_lock = threading.Lock()
devices_lock = threading.Lock()
comments_lock = threading.Lock()
devnum_lock = threading.Lock()
device_num = 0

class ServerThread(threading.Thread):
    def __init__(self, host, server_port, tls=False):
        threading.Thread.__init__(self)
        self.host = host
        self.server_port = server_port
        self.current_threads = []
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.get_num_of_devices()
        # for TLS
        self.tls = tls
        if tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain('./tls/cert.pem', './tls/key.pem')
            self.context.verify_mode = ssl.CERT_NONE
            self.server_socket = self.context.wrap_socket(self.server_socket, server_side=True)
        self.server_socket.bind((self.host, self.server_port))
        self.server_socket.listen(1)

    def run(self):
        print("Server Started, Ready to Serve...\n")
        while True:  # Serve forever
            print("listening...")
            # with self.context.wrap_socket(self.server_socket, server_side=True) as s_sock:
            try:
                connection_socket, addr = self.server_socket.accept()
                message = connection_socket.recv(4096)  # Get initial message
                if message:
                    print("Initial message received, opening new thread\n")
                    self.current_threads.append(ClientThread(connection_socket, message, self.tls))
                    self.current_threads[-1].daemon = True
                    self.current_threads[-1].start()
            except ssl.SSLError:
                pass
            except:             # Just to not let the server die
                pass

    @staticmethod
    def get_num_of_devices():
        global device_num
        with open("./data/devices.txt", 'r') as f:
            device_num = len(f.read().splitlines()) // 2

    def close(self):
        for t in self.current_threads:
            try:
                t.connSocket.shutdown(SHUT_RDWR)
                t.connSocket.close()
            except:
                pass
        self.server_socket.close()


class ClientThread(threading.Thread):
    TIMEOUT = 30

    def __init__(self, conn_socket, message, tls=True):
        threading.Thread.__init__(self)
        self.connSocket = conn_socket
        self._raw_message = message.decode("UTF-8")
        self._use_tls = tls
        self._method = "GET"
        self._path = "/"
        self._protocol = "HTTP/1.1"
        self._keep_alive = True
        self._headers = {}
        self._body = ""
        self._cur_cookie = None
        self._device_status = "*"
        # get method, path, protocol, keep_alive, headers, body for initial message
        self.parse_http()
        if self._keep_alive:
            self.connSocket.settimeout(self.TIMEOUT)

    def run(self):
        try:
            while True:     # Serve request
                # First check if redirect to https
                if not self._use_tls and USE_HTTPS and self._headers.get("Upgrade-Insecure-Requests") == "1":
                    self.send_header("301 Move Permanently", 0, "")
                    break

                if 'GET' == self._method:       # Process http GET request
                    print("Getting ", self._path)
                    extension = os.path.splitext(self._path)[1]
                    # print(extension)
                    if '/' == self._path:
                        if self._device_status == "*":
                            self._path = "./pages/index.html"
                        else:
                            self._path = "./pages/bulletin.html"
                    elif '.m3u8' == extension or '.ts' == extension:
                        self._path = "./vids" + self._path
                    else:
                        self._path = "./pages" + self._path
                    try:
                        count = os.path.getsize(self._path)
                        # extension = os.path.splitext(self._path)[1]
                        if '.png' == extension or '.jpg' == extension or '.jpeg' == extension or '.ico' == extension:
                            self.send_header("200 OK", count, "image")
                        elif '.gif' == extension:
                            self.send_header("200 OK", count, "image/gif")
                        elif '.mp3' == extension:
                            self.send_header("200 OK", count, "audio")
                        elif '.m3u8' == extension:
                            self.send_header("200 OK", count, "vnd.apple.mpegURL", ["Access-Control-Allow-Origin: *"])
                        elif '.ts' == extension:
                            self.send_header("200 OK", count, "video/MP2T", ["Access-Control-Allow-Origin: *"])
                        else:
                            self.send_header("200 OK", count, "text/html")
                        with open(self._path, 'rb') as f:
                            self.send_file(f)
                        # f.close()
                    except (FileNotFoundError, IOError):
                        count = os.path.getsize("./pages/404.html")
                        self.send_header("404 Not Found", count, "text/html")
                        f = open("./pages/404.html", 'rb')
                        self.send_file(f)
                        f.close()

                elif 'POST' == self._method:
                    self.POST_handler()
                else:
                    raise NotImplementedError("What do you want from me?")

                if self._keep_alive:            # If keep-alive, attempt to get next HTTP message.
                    message = self.connSocket.recv(4096)  # Get subsequent message
                    if message:
                        # print("Subsequent message received, handle with same thread\n")
                        self._raw_message = message.decode()
                        self.parse_http()
                        self.connSocket.settimeout(self.TIMEOUT)
                        continue
                break
        except NotImplementedError:  # send 501 message
            self.send_header("501 Not Implemented", 0, "")
        except TimeoutError:
            print("No subsequent request received. Disconnecting")
        except (IOError, OSError) as e:
            print(e)
        finally:
            # self.connSocket.shutdown(SHUT_RDWR)
            print("Closing socket.")
            self.connSocket.close()

    def parse_http(self):
        try:
            # print(self._raw_message)
            # First separate header and body:
            tmp = self._raw_message.split("\r\n\r\n")
            if len(tmp) == 2:  # this should always be True but just in case
                header, body = (tmp[0], tmp[1])
            else:
                header, body = (tmp, "")

            tmp = [i for i in header.split("\r\n")]
            if tmp[0].find('HTTP') == -1:
                raise NotImplementedError("Not HTTP request, aborting.")

            # Get HTTP method, GET request path and version of HTTP
            if len(tmp[0].split()) != 3:  # this should always be True, but just in case
                raise NotImplementedError("Wrong HTTP message")
            method, path, protocol = tmp[0].split()

            # Generate headers as a dictionary
            headers = {}
            for k, v in [i.split(':', 1) for i in tmp[1:]]:
                headers[k.strip()] = v.strip()
            # find if Connection: keep-alive is specified
            if headers.get("Connection") == "keep-alive":
                # print("This is persistent HTTP")
                keep_alive = True
            else:
                # print("This is non-persistent HTTP")
                keep_alive = False

            self._cur_cookie = headers.get("Cookie")
            self.check_cookie()
            body = body.replace('+', ' ')
            body = urllib.parse.unquote(body)

            self._method, self._path, self._protocol, self._keep_alive, self._headers, self._body = (
                (method, path, protocol, keep_alive, headers, body)
            )
            print(body)
            # return method, path, protocol, keep_alive, headers, body
        except OSError:
            self.connSocket.close()
            exit()
        except NotImplementedError:
            self.send_header("501 Not Implemented", 0, "")
            self.connSocket.close()
            exit()

    def send_header(self, status, body_len, content_type, extra=None):
        self.send_string(f"{self._protocol} {status}\r\n")  # Send one HTTP header line into socket
        self.send_string("Server: CN_phase2 server/1.0\r\n")
        now = datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')
        self.send_string(f"Date: {now}\r\n")

        if body_len > 0:  # For sending non-empty message body
            self.send_string(f"Content-Length: {body_len}\r\n")
        if content_type:
            self.send_string(f"Content-Type: {content_type}\r\n")
        if extra:
            for s in extra:
                self.send_string(f"{s}\r\n")

        if "301 Move Permanently" == status:
            self.send_string(f"Location: https://{HOST}:{HTTPS_PORT}\r\n")
            self.send_string("Vary: Upgrade-Insecure-Requests\r\n")
            self.send_string("Connection: close\r\n")
        else:
            if self._keep_alive:
                self.send_string("Connection: keep-alive\r\n")
            else:
                self.send_string("Connection: close\r\n")

        if not self._cur_cookie:
            global device_num
            devnum_lock.acquire()
            self._cur_cookie = ("dev_num=%d" % device_num)
            self.send_string("Set-Cookie: %s\r\n" % self._cur_cookie)
            device_num = device_num + 1
            devnum_lock.release()

        self.send_string("\r\n")

    def send_string(self, string):
        self.connSocket.send(string.encode())

    def send_file(self, fp):
        # For sending page other than html, Content_type has to be taken care of.
        try:
            while True:
                byte_line = fp.read(1024)
                while byte_line:             # send line directly since it's byte string
                    self.connSocket.send(byte_line)
                    # print('Sent ',repr(l))
                    byte_line = fp.read(1024)
                if not byte_line:
                    break
        except IOError:
            print("IOError when sending page file.")

    def POST_handler(self):
        inputs = self._body.split('&')
        # print(inputs)
        if len(inputs) == 2:  # login attempt
            self.login(inputs)
        elif inputs[0] == "":
            self.logout()
        elif len(inputs) == 1:
            self.comment(inputs)
        else:  # register attempt
            self.register(inputs)

    def register(self, inputs):
        name, psw, repsw = inputs[0][6:], inputs[1][4:], inputs[2][6:]
        users_lock.acquire()
        with open("./data/users.txt", 'r') as f:
            all_users = f.read().splitlines()
        users_lock.release()

        if (psw == repsw):
            self._path = "./pages/index.html"
            for u in all_users:
                u = u.split()[0]
                if name == u:  # duplicate user, alert needed
                    self._path = "./pages/register_page.html"
                    break

            if self._path == "./pages/index.html":
                add_user(name, psw)
            count = os.path.getsize(self._path)
            self.send_header("200 OK", count, "text/html")
            with open(self._path, 'rb') as f:
                self.send_file(f)
        else:
            # psw != repsw, alert needed
            count = os.path.getsize(self._path)
            self.send_header("200 OK", count, "text/html")
            with open(self._path, 'rb') as f:
                self.send_file(f)

    def login(self, inputs):
        name, psw = inputs[0][6:], inputs[1][4:]
        users_lock.acquire()
        with open("./data/users.txt", 'r') as f:
            all_users = f.read().splitlines()
        users_lock.release()

        for i in range(len(all_users)):
            user_data = all_users[i].split()
            if (name == user_data[0]):
                if psw == user_data[1]:
                    self._path = "./pages/bulletin.html"
                    count = os.path.getsize(self._path)
                    self.send_header("200 OK", count, "text/html")
                    with open(self._path, 'rb') as f:
                        self.send_file(f)

                    # modify device status
                    devices_lock.acquire()
                    modify_device_status(self._cur_cookie, name)
                    devices_lock.release()
                    self._device_status = name
                else:
                    # wrong password, alert needed
                    self._path = "./pages/index.html"
                    count = os.path.getsize(self._path)
                    self.send_header("200 OK", count, "text/html")
                    with open(self._path, 'rb') as f:
                        self.send_file(f)

        # no this account, alert needed
        self._path = "./pages/index.html"
        count = os.path.getsize(self._path)
        self.send_header("200 OK", count, "text/html")
        with open(self._path, 'rb') as f:
            self.send_file(f)

    def logout(self):
        devices_lock.acquire()
        modify_device_status(self._cur_cookie, "*")
        devices_lock.release()
        self._device_status = "*"

        self._path = "./pages/index.html"
        count = os.path.getsize(self._path)
        self.send_header("200 OK", count, "text/html")
        with open(self._path, 'rb') as f:
            self.send_file(f)

    def comment(self, inputs):
        user = self._device_status
        content = inputs[0][4:]
        comments_lock.acquire()
        add_comment(user, content)
        make_bulletin()

        self._path = "./pages/bulletin.html"
        count = os.path.getsize(self._path)
        self.send_header("200 OK", count, "text/html")
        f = open(self._path, 'rb')
        self.send_file(f)
        f.close()
        comments_lock.release()

    def check_cookie(self):
        # print(self._cur_cookie)
        devices_lock.acquire()
        with open("./data/devices.txt", 'r') as f:
            all_device = f.read().splitlines()

        for i in range(0, len(all_device), 2):
            if self._cur_cookie == all_device[i]:
                self._device_status = all_device[i + 1]
                devices_lock.release()
                return

        # No Cookie or not recognizable
        if not self._cur_cookie:
            global device_num
            devnum_lock.acquire()
            add_device("dev_num=%d" % device_num)
            devnum_lock.release()
        else:
            add_device(self._cur_cookie)
        devices_lock.release()
        self._device_status = "*"



if __name__ == "__main__":
    if USE_HTTPS:
        server_https = ServerThread(f"{HOST}", HTTPS_PORT, tls=True)
        server_https.daemon = True
        server_https.start()
    server_http = ServerThread(f"{HOST}", HTTP_PORT, tls=False)
    server_http.daemon = True
    server_http.start()
    server_http.join()

    """
    input("Press enter to stop server...")
    server_https.close()
    server_http.close()
    print("Program complete")
    """
"""
For HTTP packets larger than buffer, use this instead:

chunks = []
while True:
    # Keep reading while the client is writing.
    data = client_sock.recv(2048)
    if not data:
        # Client is done with sending.
        break
    chunks.append(data)
"""
