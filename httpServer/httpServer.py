import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import cookies
from urllib.parse import urlparse

LOGGED_IN_COOKIE = "supersecretcoookie"


class RequestHandler(BaseHTTPRequestHandler):

    def get_query_dict(self, query):
        # create a query dictionary from a query
        query = str(query).replace("'", "").replace("b\"", "").replace("\\r", "").replace("\\n", "").replace("\\", "").replace("\"", "")
        print("Parse query:", query)
        sys.stdout.flush()
        try:
            query_dict = dict()
            if "=" in query:
                parts = [(q.split("=")[0], q.split("=")[1]) for q in query.split("&")]
                for part in parts:
                    query_dict[part[0]] = part[1]
            else:
                query_dict = None
            print("Parsed output dictionary:", query_dict)
            sys.stdout.flush()
        except ValueError:
            query_dict = None

        return query_dict

    def do_GET(self):
        # handle get request
        print("\n<----- Request Start ----->\n")
        print(self.path)
        print(self.headers)
        print("<------- Request End ------->\n")
        sys.stdout.flush()

        url_parsed = urlparse(self.path)
        root_path = url_parsed.path
        query_dict = self.get_query_dict(url_parsed.query)

        # If request login page, send HTML of login page
        if self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")

            self.wfile.write(str.encode("<html><head><title>Login Page!</title></head>"))
            self.wfile.write(
                str.encode("<body><p><h1>This is the login page. Please login.</h1></p>"))
            self.wfile.write(str.encode("</body></html"))
            # self.wfile.close()

        # If request download page with proper credentials, download file
        elif root_path == "/download_file":
            if query_dict and query_dict["cookie"] == LOGGED_IN_COOKIE:
                with open("lib/fileToDownload.txt") as myFile:
                    self.wfile.write(str.encode(myFile.read()))
                    # self.wfile.close()
            else:
                self.send_response(418)
        else:
            self.send_response(404)

    def do_POST(self):
        print("\n<----- Request Start ----->\n")
        print(self.path)

        request_headers = self.headers

        # Calculate content length
        content_length = request_headers.get('content-length')
        length = int(content_length) if content_length else 0

        # Read the contents of POST request
        print(request_headers)
        request_val = self.rfile.read(length)
        print(request_val)
        print("<------- Request End ------->\n")
        sys.stdout.flush()

        # Get the query params
        query_dict = self.get_query_dict(request_val)

        # If correct log in, set the client's cookie.
        # Note that you obviouslt don't want clear-text password checking in practice...
        if self.path == "/post_login":
            if query_dict and (query_dict.get('username') == "Alex") and (
                    query_dict.get('password') == 'C0mput3rS3curity'):
                print("HERE")
                sys.stdout.flush()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                cookie = cookies.SimpleCookie()
                cookie['cookie'] = LOGGED_IN_COOKIE
                for morsel in cookie.values():
                    self.send_header("Set-Cookie", morsel.OutputString())
                self.end_headers()

        elif self.path == "/post_logout":
            self.send_response(200)
            self.send_header("Content-type", "text/html")

            # Note this logout is insecure because the user's cookie is still valid.
            self.wfile.write(str.encode("<html><head><title>Logout Page!</title></head>"))
            self.wfile.write(str.encode("<body><p><h1>You have been logged out!</h1></p>"))
            self.wfile.write(str.encode("</body></html"))
            # self.wfile.close()
        else:
            self.send_response(401)

    do_PUT = do_POST
    do_DELETE = do_GET


def main():
    # Change working directory to script's dir
    abspath = os.path.abspath(__file__)
    dirname = os.path.dirname(abspath)
    os.chdir(dirname)

    port = 8000
    source_ip = "127.1.1.1"

    print('Listening on localhost: %s' % port)
    sys.stdout.flush()
    server = HTTPServer((source_ip, port), RequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
