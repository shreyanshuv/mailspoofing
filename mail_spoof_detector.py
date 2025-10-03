#!/usr/bin/env python3
from flask import Flask, request, render_template, jsonify
import email
import dkim
import spf
import dns.resolver
import re

app = Flask(__name__, template_folder="templates")


def parse_email_from_string(raw_email):
    """
    Parse raw email from a string and return useful parts and the email.message.Message object.
    """
    try:
        msg = email.message_from_string(raw_email)
        from_addr = msg.get('From')
        to_addr = msg.get('To')
        subject = msg.get('Subject') or '(no subject)'
        received = msg.get_all('Received', [])
        return from_addr, to_addr, subject, received, msg
    except Exception as e:
        return None, None, None, [], None


def extract_sending_ip(received_headers):
    ip_pattern = re.compile(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?')
    # Search headers top-to-bottom for first IP
    for rh in (received_headers or []):
        if not rh:
            continue
        m = ip_pattern.search(rh)
        if m:
            return m.group(1)
    return None


def get_dmarc(domain):
    try:
        qname = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(qname, 'TXT', lifetime=5)
        txts = []
        for a in answers:
            # join byte parts if dnspython returns them as bytes
            try:
                txts.append("".join(part.decode() if isinstance(part, bytes) else part for part in a.strings))
            except Exception:
                txts.append(str(a))
        return " | ".join(txts) if txts else None
    except Exception:
        return None


def domain_of(addr):
    if not addr:
        return None
    m = re.search(r'@([A-Za-z0-9\.-]+)', addr)
    return m.group(1).lower() if m else None


def check_dkim(raw_bytes):
    try:
        ok = dkim.verify(raw_bytes)
        return bool(ok)
    except Exception:
        return False


def check_spf(sending_ip, helo, mailfrom):
    try:
        result, explanation = spf.check2(i=sending_ip or '', s=mailfrom or '', h=helo or '')
        return result, explanation
    except Exception as e:
        return 'temperror', str(e)


def analyze_raw_email(raw_email):
    """
    Run parsing + DKIM/SPF/DMARC heuristics and return a structured result.
    """
    from_addr, to_addr, subject, received, msg = parse_email_from_string(raw_email)
    if msg is None:
        return {'error': 'Could not parse email. Make sure you provided the raw email (headers + body).'}

    # Determine sending IP from Received headers
    sending_ip = extract_sending_ip(received)

    # Attempt to pull Return-Path/envelope-from from the message headers if present
    return_path = msg.get('Return-Path') or msg.get('Envelope-From') or ''
    # Try extract helo from first Received header
    helo = ''
    if received:
        try:
            m = re.search(r'HELO\s+([^\s;]+)', received[0], re.IGNORECASE)
            if m:
                helo = m.group(1)
        except Exception:
            helo = ''

    from_domain = domain_of(from_addr)
    return_domain = domain_of(return_path)

    # DKIM check: requires full raw bytes
    raw_bytes = raw_email.encode('utf-8', errors='replace')
    dkim_ok = check_dkim(raw_bytes)

    # SPF check (needs sending IP and envelope-from)
    if sending_ip and return_path:
        mailfrom = re.sub(r'^<|>$', '', return_path)
        spf_result, spf_explanation = check_spf(sending_ip, helo, mailfrom)
    else:
        spf_result, spf_explanation = 'none', 'No sending IP or Return-Path found; SPF skipped or unknown.'

    # DMARC policy
    dmarc_txt = get_dmarc(from_domain) if from_domain else None

    # Heuristics & scoring
    reasons = []
    score = 0

    if dkim_ok:
        score += 2
        reasons.append("Valid DKIM signature.")
    else:
        reasons.append("No valid DKIM signature.")

    if spf_result in ('pass', '+'):
        score += 2
        reasons.append(f"SPF passed ({spf_result}).")
    elif spf_result in ('fail', 'softfail'):
        reasons.append(f"SPF failed/softfail ({spf_result}).")
    else:
        reasons.append(f"SPF result: {spf_result} ({spf_explanation}).")

    if dmarc_txt:
        score += 1
        reasons.append("DMARC policy present.")
    else:
        reasons.append("No DMARC policy found or could not be read.")

    if from_domain and return_domain and from_domain != return_domain:
        reasons.append(f"From domain ({from_domain}) differs from Return-Path domain ({return_domain}) — suspicious.")

    # language heuristics
    lowered = raw_email.lower()
    if any(k in lowered for k in ('verify your account', 'urgent', 'click the link', 'password', 'suspend', 'account suspended')):
        reasons.append("Contains phishing-like language (urgency / verification request).")

    if sending_ip:
        reasons.append(f"Claimed sending IP: {sending_ip}")
    else:
        reasons.append("Could not determine sending IP from Received headers.")

    if score >= 4:
        verdict = "Likely legitimate"
    elif score >= 2:
        verdict = "Possibly spoofed — exercise caution"
    else:
        verdict = "Likely spoofed/malicious"

    return {
        'subject': subject,
        'from': from_addr,
        'return_path': return_path,
        'from_domain': from_domain,
        'return_domain': return_domain,
        'sending_ip': sending_ip,
        'dkim_ok': dkim_ok,
        'spf_result': spf_result,
        'spf_explanation': spf_explanation,
        'dmarc_txt': dmarc_txt,
        'reasons': reasons,
        'verdict': verdict
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("frontend.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    # Two ways to provide email:
    # 1) paste in textarea 'raw_email' (form)
    # 2) upload file 'eml_file' (multipart/form-data)
    raw_email = None

    # file upload path
    if 'eml_file' in request.files and request.files['eml_file'].filename:
        f = request.files['eml_file']
        try:
            raw_email = f.read().decode('utf-8', errors='replace')
        except Exception:
            raw_email = f.read().decode('latin-1', errors='replace')

    # fallback to pasted raw email
    if not raw_email:
        raw_email = request.form.get('raw_email', '')

    if not raw_email or not raw_email.strip():
        return render_template("frontend.html", error="No email provided. Paste the raw email or upload a .eml file.")

    result = analyze_raw_email(raw_email)
    return render_template("frontend.html", result=result)


@app.route("/analyze_api", methods=["POST"])
def analyze_api():
    """
    JSON API to analyze raw email. Accepts JSON: {"raw_email":"..."}
    Returns JSON analysis.
    """
    data = request.get_json(silent=True)
    if not data or 'raw_email' not in data:
        return jsonify({'error': 'Provide JSON with key raw_email'}), 400
    raw_email = data.get('raw_email') or ''
    if not raw_email.strip():
        return jsonify({'error': 'raw_email empty'}), 400

    result = analyze_raw_email(raw_email)
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True)
