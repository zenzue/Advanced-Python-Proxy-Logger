import os
import sys
import re
import json
import datetime
import threading
import zipfile
from termcolor import colored
from mitmproxy import http, ctx
import click

SENSITIVE_HEADERS = {'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-access-token'}
SENSITIVE_BODY_PATTERNS = [re.compile(r'("password"\s*:\s*")[^"]+(")', re.I),
                           re.compile(r'("access_token"\s*:\s*")[^"]+(")', re.I),
                           re.compile(r'("api_key"\s*:\s*")[^"]+(")', re.I)]
MAX_BODY_DISPLAY = 2048  # bytes
LOG_ROTATE_DAYS = 1      # days to keep logs before compressing
LOCK = threading.Lock()

def get_logfile(logdir, ext):
    date_str = datetime.datetime.now().strftime('%d-%m-%y')
    base_filename = os.path.join(logdir, f"{date_str}.{ext}")
    filename = base_filename
    idx = 1
    while os.path.exists(filename):
        filename = os.path.join(logdir, f"{date_str}_{idx}.{ext}")
        idx += 1
    return filename

def redact_headers(headers):
    return {k: ('[REDACTED]' if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}

def redact_body(body):
    if not body:
        return body
    body_str = body if isinstance(body, str) else str(body)
    for pattern in SENSITIVE_BODY_PATTERNS:
        body_str = pattern.sub(r'\1[REDACTED]\2', body_str)
    return body_str

def compress_old_logs(logdir, ext):
    now = datetime.datetime.now()
    for fname in os.listdir(logdir):
        if fname.endswith(f".{ext}"):
            path = os.path.join(logdir, fname)
            ctime = datetime.datetime.fromtimestamp(os.path.getctime(path))
            if (now - ctime).days >= LOG_ROTATE_DAYS:
                zfname = path + ".zip"
                with zipfile.ZipFile(zfname, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.write(path, arcname=fname)
                os.remove(path)

def filter_flow(flow, filters):
    if not filters:
        return True
    if filters.get("host") and filters["host"] not in flow.request.host:
        return False
    if filters.get("method") and filters["method"] != flow.request.method:
        return False
    if filters.get("keyword"):
        data = flow.request.get_text() + flow.response.get_text() if flow.response else flow.request.get_text()
        if filters["keyword"] not in data:
            return False
    if filters.get("content_type"):
        ct = flow.response.headers.get("content-type", "") if flow.response else flow.request.headers.get("content-type", "")
        if filters["content_type"] not in ct:
            return False
    return True

def color_status(status_code):
    if 200 <= status_code < 300:
        return colored(str(status_code), "green")
    elif 300 <= status_code < 400:
        return colored(str(status_code), "yellow")
    elif 400 <= status_code < 500:
        return colored(str(status_code), "red")
    else:
        return colored(str(status_code), "magenta")

class AdvancedTrafficLogger:
    def __init__(self, logdir="logs", loglevel="INFO", filter_host=None, filter_method=None, filter_keyword=None, filter_content_type=None):
        os.makedirs(logdir, exist_ok=True)
        self.logdir = logdir
        self.loglevel = loglevel
        self.txt_logfile = get_logfile(logdir, "log")
        self.json_logfile = get_logfile(logdir, "json")
        self.filters = {
            "host": filter_host,
            "method": filter_method,
            "keyword": filter_keyword,
            "content_type": filter_content_type
        }

    def log_text(self, msg):
        with LOCK:
            with open(self.txt_logfile, "a", encoding="utf-8") as f:
                f.write(msg + "\n" + ("="*100) + "\n")

    def log_json(self, data):
        with LOCK:
            with open(self.json_logfile, "a", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
                f.write("\n")

    def summary_console(self, flow, status_code, req_len, res_len):
        print(
            f"{colored(datetime.datetime.now().strftime('%H:%M:%S'), 'cyan')} "
            f"{flow.request.method} {colored(flow.request.pretty_url, 'blue')} "
            f"→ {color_status(status_code)} | Req: {req_len}B, Res: {res_len}B"
        )

    def request(self, flow: http.HTTPFlow):
        if not filter_flow(flow, self.filters):
            return
        try:
            client_ip = flow.client_conn.address[0] if flow.client_conn else "unknown"
            req = flow.request
            req_body = req.get_text() if req.raw_content else None
            req_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "client_ip": client_ip,
                "method": req.method,
                "url": req.pretty_url,
                "headers": redact_headers(dict(req.headers)),
                "body": redact_body(req_body) if req_body else None,
                "http_version": req.http_version,
                "session_id": id(flow.client_conn),
                "type": "request"
            }
            display_body = redact_body(req_body)
            if display_body and len(display_body) > MAX_BODY_DISPLAY:
                display_body = display_body[:MAX_BODY_DISPLAY] + " ... [TRUNCATED]"
            self.log_text(
                f"[REQUEST] {req.method} {req.pretty_url} | {client_ip}\n"
                f"Headers: {json.dumps(redact_headers(dict(req.headers)), indent=2)}\n"
                f"Body: {display_body}"
            )
            self.log_json(req_data)
        except Exception as e:
            ctx.log.warn(f"Request logging error: {e}")

    def response(self, flow: http.HTTPFlow):
        if not filter_flow(flow, self.filters):
            return
        try:
            client_ip = flow.client_conn.address[0] if flow.client_conn else "unknown"
            res = flow.response
            req = flow.request
            res_body = None
            if res.raw_content:
                try:
                    res_body = res.get_text()
                except Exception:
                    res_body = "[BINARY CONTENT]"
            res_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "client_ip": client_ip,
                "status_code": res.status_code,
                "url": req.pretty_url,
                "headers": redact_headers(dict(res.headers)),
                "body": redact_body(res_body) if res_body else None,
                "http_version": res.http_version,
                "session_id": id(flow.client_conn),
                "type": "response"
            }
            display_body = redact_body(res_body)
            if display_body and len(display_body) > MAX_BODY_DISPLAY:
                display_body = display_body[:MAX_BODY_DISPLAY] + " ... [TRUNCATED]"
            self.log_text(
                f"[RESPONSE] {res.status_code} {req.pretty_url} | {client_ip}\n"
                f"Headers: {json.dumps(redact_headers(dict(res.headers)), indent=2)}\n"
                f"Body: {display_body}"
            )
            self.log_json(res_data)
            self.summary_console(flow, res.status_code, len(req.raw_content or b''), len(res.raw_content or b''))
        except Exception as e:
            ctx.log.warn(f"Response logging error: {e}")

    def done(self):
        compress_old_logs(self.logdir, "log")
        compress_old_logs(self.logdir, "json")
        print(colored("Logs compressed, proxy shutting down.", "yellow"))

@click.command()
@click.option('--logdir', default='logs', help='Directory to save logs')
@click.option('--port', default=8080, help='Proxy listen port')
@click.option('--loglevel', default='INFO', help='Log level')
@click.option('--filter-host', default=None, help='Log only traffic matching host substring')
@click.option('--filter-method', default=None, help='Log only specific HTTP method')
@click.option('--filter-keyword', default=None, help='Log only if keyword appears in request/response')
@click.option('--filter-content-type', default=None, help='Log only if Content-Type matches substring')
def main(logdir, port, loglevel, filter_host, filter_method, filter_keyword, filter_content_type):
    """
    Enterprise-Grade HTTP/HTTPS Proxy Logger for Security Analysis.
    """
    logger = AdvancedTrafficLogger(
        logdir=logdir,
        loglevel=loglevel,
        filter_host=filter_host,
        filter_method=filter_method,
        filter_keyword=filter_keyword,
        filter_content_type=filter_content_type,
    )
    global addons
    addons = [logger]
    print(colored(f"Proxy logger running on port {port}, logging to {logdir}", "cyan"))
    print(colored("Press Ctrl+C to stop. Logs will be compressed.", "yellow"))

if __name__ == '__main__':
    main()
