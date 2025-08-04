import socket
import os
import hashlib
import urllib.parse
import sqlite3
conn = sqlite3.connect("login.db", check_same_thread=False)
ROUTES = {}
import uuid

sessions = {}  # session_id -> username


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
        return handler(request)

    # Only use static route if the path is not "/"
    if path != "/" and request is not None:
        static_response = static_file_route(request)
        if static_response is not None:
            return static_response

    return "HTTP/1.1 404 NOT FOUND\n\nPage not found."


def hash_password(password):
    """Generate a random salt and hash the password. Returns (salt_hex, hash_hex)."""
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return salt.hex(), hashed.hex()

def hash_password_with_salt(password,salt):
    """Hash the password with the given salt."""
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 100_000)
    return hashed.hex()

# This function parses the form data from the HTTP request body and returns it as a Python dictionary.
def parse_form_data(request):
    """Extracts form data from the HTTP request body and returns a dict."""
    try:
        body = request.split('\r\n\r\n', 1)[1]
    except (IndexError, AttributeError):
        return {}
    # Decode URL-encoded form data
    return dict(urllib.parse.parse_qsl(body))

def parse_cookies(request):
    cookies = {}
    try:
        headers = request.split('\r\n\r\n', 1)[0]
        for line in headers.split('\r\n'):
            if line.lower().startswith("cookie:"):
                parts = line.split(":", 1)[1].strip().split("; ")
                for part in parts:
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cookies[k] = v
    except:
        pass
    return cookies




def start_server():
    server_socket = socket.socket()
    server_socket.bind(('localhost', 8400))
    server_socket.listen(1)
    print("Listening on http://localhost:8400")

    while True:
        client_connection, client_address = server_socket.accept()  # waits for a client to connect
        request = b""
        
        while True:
            chunk = client_connection.recv(1024)
            request += chunk
            if len(chunk) < 1024:
                break
        
        request = request.decode()
        print(f"Received request:\n{request}")

        response = handle_request(request)
        if isinstance(response, bytes):
            client_connection.sendall(response)
        else:
            client_connection.sendall(response.encode())
        
        client_connection.close()

        

        # This route serves login requests
@route("/api/login")
def login(request):
    # This part extracts (parses) the data from the request
    params = parse_form_data(request)
    username = params.get('username')
    password = params.get('password')
    # Check if username and password are provided
    if not username or not password:
        return "HTTP/1.1 400 BAD REQUEST\n\nMissing username or password."

    # Attempt to login by asking database for user-pass hash combo

    # connect to database
    cursor = conn.cursor()
    # Get this user's salt
    cursor.execute("SELECT salt, password_hash FROM users WHERE username=?", (username,))
    # Fetch the result
    # If the user does not exist, this will return None, a type of Python object that is basically "nothing"
    result = cursor.fetchone()
    if not result:
        # If the result is None, it means the user does not exist. 
        # Don't tell the user if it's the username or password that is wrong, just say "login failed"
        # This is a security measure to prevent attackers from knowing if the username exists.
        # This prevents brute force attacks where an attacker tries to guess the username and password.
        return "HTTP/1.1 401 UNAUTHORIZED\n\nLogin failed: Invalid username or password."
    # If the user exists, we get the salt and password hash from the database
    salt, stored_hash = result
    # Now we hash the password with the salt we got from the database
    password_hash = hash_password_with_salt(password, salt)
    if password_hash != stored_hash:
        return "HTTP/1.1 401 UNAUTHORIZED\n\nLogin failed: Invalid username or password."

    # ✅ Generate session ID and store it
    session_id = str(uuid.uuid4())
    sessions[session_id] = username

    # ✅ Send Set-Cookie header to store the session ID in the browser
    return (
    "HTTP/1.1 302 FOUND\n"
    f"Set-Cookie: session_id={session_id}; Path=/\n"
    "Location: /\n"
    "\n"
)



@route("/api/logout")
def logout(request):
    cookies = parse_cookies(request)
    session_id = cookies.get("session_id")
    if session_id and session_id in sessions:
        del sessions[session_id]
    return (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: session_id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT\n"
        "\nLogged out!"
    )


@route("/dashboard")
def get_dashboard(request):

    cookies = parse_cookies(request)  # Make sure to pass `request` to the route
    session_id = cookies.get("session_id")
    username = sessions.get(session_id)

    if username:
        return get_file("dashboard.html")
    else:
        return "HTTP/1.1 403 FORBIDDEN\n\nYou must be logged in to view this page."


@route("/api/create_account")
def create_account(request):
    # Extract the form data from the request
    params = parse_form_data(request)
    username = params.get('username')
    password = params.get('password')
    first_name = params.get('first_name')
    last_name = params.get('last_name')
    email = params.get('email')

    # Check if all fields are provided
    if not username or not password or not first_name or not last_name or not email:
        return "HTTP/1.1 400 BAD REQUEST\n\nMissing required fields."

    cursor = conn.cursor()
    salt, password_hash = hash_password(password)
    try:
        # Insert user into database
        cursor.execute("INSERT INTO users (username, salt, password_hash, first_name, last_name, email) VALUES (?, ?, ?, ?, ?, ?)",
                       (username, salt, password_hash, first_name, last_name, email))
        conn.commit()

        # Automatically log in the new user by creating a session
        session_id = str(uuid.uuid4())
        sessions[session_id] = username

        # Redirect to homepage like the login route
        return (
            "HTTP/1.1 302 FOUND\n"
            f"Set-Cookie: session_id={session_id}; Path=/\n"
            "Location: /\n"
            "\n"
        )

    except sqlite3.IntegrityError:
        return "HTTP/1.1 409 CONFLICT\n\nUsername already exists."

    
    

@route("/")
def get_index(request):
    # Check for login
  # uses the current request captured by handle_request
    cookies = parse_cookies(request)
    session_id = cookies.get("session_id")
    username = sessions.get(session_id)
    print("🍪 COOKIES:", cookies)
    print("🙋 SESSION ID:", session_id)
    print("🙋 USERNAME:", username)
    

    greeting_html = '<li><a href="/login">Log In</a></li>'
    
    if username:
        cursor = conn.cursor()
        cursor.execute("SELECT first_name FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            first_name = row[0]
            greeting_html = f'<li><span class="greeting">Hi, {first_name}</span></li>'

    # Manually insert the greeting into the HTML
    base_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base_dir, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()
    
    html = html.replace("{{greeting}}", greeting_html)
    return f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{html}"


@route("/contact")
def contact_page(request):
    return get_file("contact.html")

@route("/clothes")
def clothes_page(request):
    return get_file("products.html")

@route("/login")
def login_page(request):
    return get_file("LogIn.html")

@route("/list")
def list_page(request):
    return get_file("list.html")

@route("/signup")
def signup_page(request):
    return get_file("signup.html")




start_server()