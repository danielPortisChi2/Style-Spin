import socket
import os

ROUTES = {}

def route(path):
    """Register a function as a route handler."""
    def decorator(func):
        ROUTES[path] = func
        return func
    return decorator

def get_file(filename, content_type="text/html"):
    """Retrieve a file from the server's directory and return its content
    as an HTTP response."""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, filename)
        if content_type.startswith("image/"):
            with open(file_path, "rb") as f:
                content = f.read()
            header = f"HTTP/1.1 200 OK\nContent-Type: {content_type}\n\n"
            response = header.encode("utf-8") + content
            return response
        else:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return f"HTTP/1.1 200 OK\nContent-Type: {content_type}\n\n{content}"
    except Exception:
        if content_type.startswith("image/"):
            return b"HTTP/1.1 500 INTERNAL SERVER ERROR\n\nError loading file: " + filename.encode("utf-8")
        else:
            return f"HTTP/1.1 500 INTERNAL SERVER ERROR\n\nError loading file: {filename}"

def static_file_route(request, filename=None):
    if request == '':
        return None
    path = request.split(" ")[1]
    # Remove leading slash if present
    filename = path.lstrip("/")
    if not filename:
        return None  # No file specified, let normal routing handle
    ext = os.path.splitext(filename)[1].lower()
    # Only serve files with known static extensions
    content_type = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".webp": "image/webp",
        ".avif": "image/avif",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".css": "text/css",
        ".js": "application/javascript",
        ".json": "application/json",
        ".xml": "application/xml",
        ".pdf": "application/pdf",
        ".txt": "text/plain",
    }
    if ext in content_type:
        # Check if the file exists in the current directory
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, filename)
        if os.path.isfile(file_path):
            return get_file(filename, content_type[ext])
    return None  # No static file found, let normal routing handle
# Patch handle_request to check static files if no route matches

def handle_request(request):
    try:
        path = request.split(" ")[1]
    except IndexError:
        path = "/"
    handler = ROUTES.get(path)
    if handler:
        return handler()
    # Check for static files (e.g., /images/filename)
    if request is not None:
        static_response = static_file_route(request)
    if static_response is not None:
        return static_response
    return "HTTP/1.1 404 NOT FOUND\n\nPage not found."

def start_server():
    server_socket = socket.socket()
    server_socket.bind(('localhost', 8000))
    server_socket.listen(1)
    print("Listening on http://localhost:8000")
    while True:
        client_connection, client_address = server_socket.accept() # this line waits for a client to connect 
        request = client_connection.recv(1024).decode()
        print(f"Received request:\n{request}")
        response = handle_request(request)
        if isinstance(response, bytes):
            client_connection.sendall(response)
        else:
            client_connection.sendall(response.encode())
        client_connection.close() 

@route("/")
def get_index():
    return get_file("index.html")

@route("/contact")
def get_index():
    return get_file("contact.html")

@route("/clothes")
def get_index():
    return get_file("products.html")

@route("/login")
def get_index():
    return get_file("LogIn.html")

@route("/list")
def get_index():
    return get_file("list.html")

@route("/signup")
def get_index():
    return get_file("signup.html")



start_server()