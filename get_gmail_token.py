"""
get_gmail_token.py - run ONCE on your own computer (not on Render).

It signs you in to Google in your browser and prints the GMAIL_REFRESH_TOKEN
that lets the iMatiz server send email from your Gmail account through the
Gmail API (HTTPS). Render's free plan blocks normal Gmail SMTP, but not this.

Usage:
    python get_gmail_token.py
Then paste the Client ID and Client secret from Google Cloud when asked, and
sign in with the Gmail account that should SEND the emails
(e.g. santhoshimatiz@gmail.com). Nothing to install - standard library only.
"""
import base64
import hashlib
import http.server
import json
import secrets
import socket
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser

SCOPE = "https://www.googleapis.com/auth/gmail.send"


def main():
    print(__doc__)
    client_id = input("Client ID: ").strip()
    client_secret = input("Client secret: ").strip()
    if not client_id or not client_secret:
        sys.exit("Both the Client ID and Client secret are needed.")

    # Loopback redirect on a free local port (Desktop-app OAuth clients allow any port).
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    redirect_uri = "http://127.0.0.1:%d/" % port

    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16)
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": SCOPE, "access_type": "offline", "prompt": "consent",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state})

    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" in q or "error" in q:
                result.update({k: v[0] for k, v in q.items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<h2>Done - you can close this tab and go back to the terminal.</h2>")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.handle_request, daemon=True)
    t.start()

    print("\nOpening your browser to sign in to Google...")
    print("If it doesn't open, copy this link into your browser:\n\n%s\n" % auth_url)
    print("Tip: if Google says the app isn't verified, click Advanced -> Go to ... (unsafe).")
    print("That warning is shown because this is your own private app.\n")
    webbrowser.open(auth_url)
    t.join(timeout=600)
    server.server_close()

    if result.get("error"):
        sys.exit("Google returned an error: %s" % result["error"])
    if result.get("state") != state or not result.get("code"):
        sys.exit("Didn't get a valid sign-in response. Please run the script again.")

    data = urllib.parse.urlencode({
        "code": result["code"], "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect_uri, "grant_type": "authorization_code",
        "code_verifier": verifier}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(
                "https://oauth2.googleapis.com/token", data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=30) as r:
            tokens = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        sys.exit("Token exchange failed: %s" % e.read().decode())

    refresh = tokens.get("refresh_token")
    if not refresh:
        sys.exit("Google didn't return a refresh token. Remove this app's access at "
                 "https://myaccount.google.com/permissions and run the script again.")

    print("=" * 70)
    print("SUCCESS. Add these 3 variables in Render -> your web service -> Environment:\n")
    print("GMAIL_CLIENT_ID=%s" % client_id)
    print("GMAIL_CLIENT_SECRET=%s" % client_secret)
    print("GMAIL_REFRESH_TOKEN=%s" % refresh)
    print("\nKeep GMAIL_USER set to the same Gmail address you just signed in with.")
    print("=" * 70)


if __name__ == "__main__":
    main()
