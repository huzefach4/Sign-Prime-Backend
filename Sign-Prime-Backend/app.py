import os
import json
import uuid
import bcrypt
import jwt
import datetime
import base64
import certifi
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from PyPDF2 import PdfReader, PdfWriter
from functools import wraps
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv

import firebase_admin
from firebase_admin import credentials, firestore, storage
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import io
os.environ["SSL_CERT_FILE"] = certifi.where()

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ─── Environment Checks ───────────────────────────────────────────────────────

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL")
SENDGRID_FROM_NAME = os.getenv("SENDGRID_FROM_NAME", "SignPrime")
JWT_SECRET = os.getenv("JWT_SECRET", "fallback-secret")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
FIREBASE_STORAGE_BUCKET = os.getenv("FIREBASE_STORAGE_BUCKET")

print("Bucket:", FIREBASE_STORAGE_BUCKET)
print("SendGrid From Email:", SENDGRID_FROM_EMAIL)
print("Frontend URL:", FRONTEND_URL)

if not SENDGRID_API_KEY:
    print("WARNING: SENDGRID_API_KEY is missing in .env")

if not SENDGRID_FROM_EMAIL:
    print("WARNING: SENDGRID_FROM_EMAIL is missing in .env")

if JWT_SECRET == "fallback-secret":
    print("WARNING: JWT_SECRET is using fallback-secret. Set a real JWT_SECRET in .env")

# ─── Firebase Init ────────────────────────────────────────────────────────────

if not firebase_admin._apps:
    cred = credentials.Certificate("/etc/secrets/firebase-service-account.json")
    firebase_admin.initialize_app(cred, {
        "storageBucket": FIREBASE_STORAGE_BUCKET
    })

db = firestore.client()
bucket = storage.bucket()


# ─── PDF Font Setup ───────────────────────────────────────────────────────────

FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")

SIGNATURE_FONT_FILES = {
    "Dancing Script": "DancingScript-Regular.ttf",
    "Great Vibes": "GreatVibes-Regular.ttf",
    "Pacifico": "Pacifico-Regular.ttf",
    "Pinyon Script": "PinyonScript-Regular.ttf",
}

AVAILABLE_SIGNATURE_FONTS = set()

for font_name, font_file in SIGNATURE_FONT_FILES.items():
    font_path = os.path.join(FONT_DIR, font_file)

    if os.path.exists(font_path):
        try:
            pdfmetrics.registerFont(TTFont(font_name, font_path))
            AVAILABLE_SIGNATURE_FONTS.add(font_name)
            print(f"PDF font registered: {font_name}")
        except Exception as e:
            print(f"PDF font registration failed for {font_name}:", str(e))
    else:
        print(f"PDF font file missing: {font_path}")


def get_pdf_signature_font(signature_font):
    if signature_font in AVAILABLE_SIGNATURE_FONTS:
        return signature_font

    return "Helvetica-Oblique"


# ─── Health Check ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "SignPrime backend running",
        "version": "1.0",
        "environment": os.getenv("FLASK_ENV"),
        "sendgrid_configured": bool(SENDGRID_API_KEY and SENDGRID_FROM_EMAIL),
        "firebase_bucket": FIREBASE_STORAGE_BUCKET
    })


# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def generate_token(user_id, email):
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        print("TOKEN ERROR:", str(e))
        return None


def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")

        payload = verify_token(token)

        if not payload:
            return jsonify({"error": "Unauthorized"}), 401

        request.user = payload
        return f(*args, **kwargs)

    return decorated


def log_activity(doc_id, sender_id, action, details=""):
    db.collection("activities").add({
        "document_id": doc_id,
        "sender_id": sender_id,
        "action": action,
        "details": details,
        "timestamp": firestore.SERVER_TIMESTAMP
    })


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    try:
        data = request.json or {}

        email = data.get("email", "").lower().strip()
        password = data.get("password", "")
        name = data.get("name", "").strip()

        if not email or not password or not name:
            return jsonify({"error": "All fields required"}), 400

        existing = db.collection("users").where("email", "==", email).limit(1).get()

        if len(existing) > 0:
            return jsonify({"error": "Email already registered"}), 409

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user_id = str(uuid.uuid4())

        db.collection("users").document(user_id).set({
            "id": user_id,
            "email": email,
            "name": name,
            "password": hashed,
            "created_at": firestore.SERVER_TIMESTAMP
        })

        token = generate_token(user_id, email)

        return jsonify({
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "name": name
            }
        }), 201

    except Exception as e:
        print("REGISTER ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.json or {}

        email = data.get("email", "").lower().strip()
        password = data.get("password", "")

        users = db.collection("users").where("email", "==", email).limit(1).get()

        if not users:
            return jsonify({"error": "Invalid credentials"}), 401

        user_doc = users[0]
        user = user_doc.to_dict()

        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({"error": "Invalid credentials"}), 401

        token = generate_token(user["id"], email)

        return jsonify({
            "token": token,
            "user": {
                "id": user["id"],
                "email": email,
                "name": user["name"]
            }
        }), 200

    except Exception as e:
        print("LOGIN ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/auth/me", methods=["GET"])
@auth_required
def me():
    user_doc = db.collection("users").document(request.user["user_id"]).get()

    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404

    u = user_doc.to_dict()

    return jsonify({
        "id": u["id"],
        "email": u["email"],
        "name": u["name"]
    }), 200


# ─── Document Routes ──────────────────────────────────────────────────────────

@app.route("/api/documents/upload", methods=["POST"])
@auth_required
def upload_document():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]

        if not file.filename.lower().endswith(".pdf"):
            return jsonify({"error": "Only PDF files allowed"}), 400

        title = request.form.get("title", file.filename)
        recipients_raw = request.form.get("recipients", "[]")
        message = request.form.get("message", "")

        try:
            recipients = json.loads(recipients_raw)
        except Exception:
            recipients = []

        if not recipients:
            return jsonify({"error": "At least one recipient required"}), 400

        doc_id = str(uuid.uuid4())

        blob = bucket.blob(f"documents/{doc_id}/original.pdf")
        blob.upload_from_file(file, content_type="application/pdf")

        try:
            blob.make_public()
            pdf_url = blob.public_url
        except Exception as e:
            print("MAKE PUBLIC ERROR:", str(e))
            pdf_url = ""

        recipient_list = []

        for r in recipients:
            email = r.get("email", "").lower().strip()
            name = r.get("name", email).strip() if r.get("name") else email

            if email:
                recipient_list.append({
                    "email": email,
                    "name": name,
                    "token": str(uuid.uuid4()),
                    "status": "pending"
                })

        if not recipient_list:
            return jsonify({"error": "Recipient email is required"}), 400

        db.collection("documents").document(doc_id).set({
            "id": doc_id,
            "title": title,
            "sender_id": request.user["user_id"],
            "pdf_url": pdf_url,
            "recipients": recipient_list,
            "message": message,
            "sign_locations": [],
            "status": "draft",
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        log_activity(
            doc_id,
            request.user["user_id"],
            "document_uploaded",
            f"Uploaded: {title}"
        )

        return jsonify({
            "id": doc_id,
            "pdf_url": pdf_url,
            "recipients": recipient_list
        }), 201

    except Exception as e:
        print("UPLOAD ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents", methods=["GET"])
@auth_required
def list_documents():
    try:
        docs = (
            db.collection("documents")
            .where("sender_id", "==", request.user["user_id"])
            .order_by("created_at", direction=firestore.Query.DESCENDING)
            .get()
        )

        result = []

        for doc in docs:
            d = doc.to_dict()
            d.pop("sign_locations", None)
            result.append(d)

        return jsonify(result), 200

    except Exception as e:
        print("LIST DOCUMENTS ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents/<doc_id>", methods=["GET"])
@auth_required
def get_document(doc_id):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        return jsonify(d), 200

    except Exception as e:
        print("GET DOCUMENT ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents/<doc_id>/preview", methods=["GET"])
def preview_document(doc_id):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Document not found"}), 404

        d = doc.to_dict()

        blob = bucket.blob(f"documents/{doc_id}/original.pdf")

        if not blob.exists():
            return jsonify({"error": "PDF file not found in Firebase Storage"}), 404

        pdf_bytes = blob.download_as_bytes()

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=False,
            download_name=f"{d.get('title', 'document')}.pdf"
        )

    except Exception as e:
        print("PREVIEW ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/documents/<doc_id>/page-count", methods=["GET"])
@auth_required
def get_document_page_count(doc_id):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Document not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        blob = bucket.blob(f"documents/{doc_id}/original.pdf")

        if not blob.exists():
            return jsonify({"error": "PDF file not found in Firebase Storage"}), 404

        pdf_bytes = blob.download_as_bytes()
        reader = PdfReader(io.BytesIO(pdf_bytes))

        return jsonify({
            "pages": len(reader.pages)
        }), 200

    except Exception as e:
        print("PAGE COUNT ERROR:", str(e))
        return jsonify({"error": "Failed to read PDF page count"}), 500

@app.route("/api/documents/<doc_id>/locations", methods=["PUT"])
@auth_required
def update_locations(doc_id):
    try:
        doc_ref = db.collection("documents").document(doc_id)
        doc = doc_ref.get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        data = request.json or {}
        locations = data.get("locations", [])

        valid_recipient_emails = {
            r.get("email", "").lower().strip()
            for r in d.get("recipients", [])
            if r.get("email")
        }

        cleaned_locations = []
        for index, loc in enumerate(locations):
            loc = dict(loc or {})
            recipient_email = (
                loc.get("recipientEmail")
                or loc.get("recipient_email")
                or ""
            ).lower().strip()

            if not recipient_email or recipient_email not in valid_recipient_emails:
                return jsonify({
                    "error": f"Field {index + 1} is not assigned to a valid recipient"
                }), 400

            recipient = next(
                (r for r in d.get("recipients", []) if r.get("email", "").lower().strip() == recipient_email),
                {}
            )

            loc["recipientEmail"] = recipient_email
            loc["recipientName"] = loc.get("recipientName") or recipient.get("name") or recipient_email
            loc["recipientIndex"] = int(loc.get("recipientIndex", 0) or 0)
            cleaned_locations.append(loc)

        locations = cleaned_locations

        doc_ref.update({
            "sign_locations": locations,
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        log_activity(
            doc_id,
            request.user["user_id"],
            "locations_updated",
            f"Updated {len(locations)} sign location(s)"
        )

        return jsonify({"success": True}), 200

    except Exception as e:
        print("UPDATE LOCATIONS ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents/<doc_id>/send", methods=["POST"])
@auth_required
def send_document(doc_id):
    try:
        if not SENDGRID_API_KEY:
            return jsonify({
                "success": False,
                "error": "SENDGRID_API_KEY is missing in .env"
            }), 500

        if not SENDGRID_FROM_EMAIL:
            return jsonify({
                "success": False,
                "error": "SENDGRID_FROM_EMAIL is missing in .env"
            }), 500

        doc_ref = db.collection("documents").document(doc_id)
        doc = doc_ref.get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        data = request.json or {}
        message = data.get("message", d.get("message", ""))

        sender_doc = db.collection("users").document(request.user["user_id"]).get()
        sender_data = sender_doc.to_dict() if sender_doc.exists else {}
        sender_name = sender_data.get("name", "Someone")

        recipients = d.get("recipients", [])

        if not recipients:
            return jsonify({
                "success": False,
                "error": "No recipients found for this document"
            }), 400

        sent_count = 0
        failed_recipients = []
        sg = SendGridAPIClient(SENDGRID_API_KEY)

        for recipient in recipients:
            recipient_email = recipient.get("email", "").lower().strip()
            recipient_name = recipient.get("name", recipient_email)
            recipient_token = recipient.get("token")

            if not recipient_email or not recipient_token:
                failed_recipients.append({
                    "email": recipient_email,
                    "error": "Missing recipient email or token"
                })
                continue

            sign_url = f"{FRONTEND_URL}/sign/{doc_id}/{recipient_token}"

            html = _build_email_html(
                sender_name=sender_name,
                doc_title=d.get("title", "Document"),
                message=message,
                sign_url=sign_url,
                recipient_name=recipient_name
            )

            mail = Mail(
                from_email=(SENDGRID_FROM_EMAIL, SENDGRID_FROM_NAME),
                to_emails=recipient_email,
                subject=f"{sender_name} requests your signature on \"{d.get('title', 'Document')}\"",
                html_content=html
            )

            try:
                response = sg.send(mail)

                print("──────────────── SENDGRID RESPONSE ────────────────")
                print("Recipient:", recipient_email)
                print("Status:", response.status_code)
                print("Body:", response.body)
                print("Headers:", response.headers)
                print("──────────────────────────────────────────────────")

                if response.status_code in [200, 202]:
                    sent_count += 1
                else:
                    failed_recipients.append({
                        "email": recipient_email,
                        "error": f"SendGrid returned status {response.status_code}"
                    })

            except Exception as e:
                print("──────────────── SENDGRID ERROR ────────────────")
                print("Recipient:", recipient_email)
                print("Error Type:", type(e).__name__)
                print("Error:", str(e))

                error_body = ""
                error_status = ""

                if hasattr(e, "status_code"):
                    error_status = e.status_code
                    print("SendGrid Error Status:", e.status_code)

                if hasattr(e, "body"):
                    error_body = e.body
                    print("SendGrid Error Body:", e.body)

                if hasattr(e, "headers"):
                    print("SendGrid Error Headers:", e.headers)

                print("───────────────────────────────────────────────")

                failed_recipients.append({
                    "email": recipient_email,
                    "error": str(error_body) if error_body else str(e),
                    "status": error_status
                })

        if sent_count == 0:
            log_activity(
                doc_id,
                request.user["user_id"],
                "document_send_failed",
                f"Email failed for all recipients. Message: {message}"
            )

            return jsonify({
                "success": False,
                "error": "Email was not sent. Check backend terminal for SendGrid error details.",
                "sent_count": sent_count,
                "failed_recipients": failed_recipients
            }), 500

        doc_ref.update({
            "status": "sent",
            "updated_at": firestore.SERVER_TIMESTAMP,
            "message": message
        })

        log_activity(
            doc_id,
            request.user["user_id"],
            "document_sent",
            f"Sent to {sent_count} recipient(s). Message: {message}"
        )

        return jsonify({
            "success": True,
            "sent_count": sent_count,
            "failed_recipients": failed_recipients
        }), 200

    except Exception as e:
        print("SEND DOCUMENT ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents/<doc_id>", methods=["DELETE"])
@auth_required
def delete_document(doc_id):
    try:
        doc_ref = db.collection("documents").document(doc_id)
        doc = doc_ref.get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        log_activity(
            doc_id,
            request.user["user_id"],
            "document_deleted",
            f"Deleted: {d.get('title', '')}"
        )

        doc_ref.delete()

        return jsonify({"success": True}), 200

    except Exception as e:
        print("DELETE DOCUMENT ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents/<doc_id>/activities", methods=["GET"])
@auth_required
def get_activities(doc_id):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        acts = (
            db.collection("activities")
            .where("document_id", "==", doc_id)
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .get()
        )

        result = []

        for a in acts:
            ad = a.to_dict()

            if ad.get("timestamp"):
                ad["timestamp"] = ad["timestamp"].isoformat()

            result.append(ad)

        return jsonify(result), 200

    except Exception as e:
        print("ACTIVITIES ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/documents/<doc_id>/download", methods=["GET"])
@auth_required
def sender_download(doc_id):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        if d.get("sender_id") != request.user["user_id"]:
            return jsonify({"error": "Forbidden"}), 403

        signed_pdf_url = d.get("latest_signed_pdf_url", "")

        recipients = d.get("recipients", [])

        if not signed_pdf_url and d.get("status") in ["completed", "partial"]:
            signed_recipient = next(
                (r for r in reversed(recipients) if r.get("signed_pdf_url")),
                None
            )

            if signed_recipient:
                signed_pdf_url = signed_recipient.get("signed_pdf_url", "")

        log_activity(
            doc_id,
            request.user["user_id"],
            "document_downloaded",
            "Sender downloaded document"
        )

        return jsonify({
            "pdf_url": signed_pdf_url or d.get("pdf_url", "")
        }), 200

    except Exception as e:
        print("DOWNLOAD ERROR:", str(e))
        return jsonify({"error": str(e)}), 500



# ─── PDF Signing Helper ───────────────────────────────────────────────────────

def create_signed_pdf(doc_id, d, recipient, signature_text, signature_font="Dancing Script", signature_image_b64=""):
    """
    Creates a new signed PDF from the original PDF.
    - Signature fields receive the user's signature.
    - Typed signatures use registered TTF fonts when available.
    - Datetime fields receive the current date/time automatically.
    - The signed PDF is uploaded to Firebase Storage and a public URL is returned.
    """
    latest_signed_pdf_path = d.get("latest_signed_pdf_path")

    if latest_signed_pdf_path:
        base_blob = bucket.blob(latest_signed_pdf_path)
    else:
        base_blob = bucket.blob(f"documents/{doc_id}/original.pdf")

    if not base_blob.exists():
        base_blob = bucket.blob(f"documents/{doc_id}/original.pdf")

    if not base_blob.exists():
        raise Exception("Original PDF not found in Firebase Storage")

    base_pdf_bytes = base_blob.download_as_bytes()

    reader = PdfReader(io.BytesIO(base_pdf_bytes))
    writer = PdfWriter()

    signed_at_text = datetime.datetime.now().strftime("%d-%m-%Y %I:%M %p")

    signature_image = None
    if signature_image_b64 and signature_image_b64.startswith("data:image"):
        try:
            image_data = signature_image_b64.split(",", 1)[1]
            image_bytes = base64.b64decode(image_data)
            signature_image = ImageReader(io.BytesIO(image_bytes))
        except Exception as e:
            print("SIGNATURE IMAGE DECODE ERROR:", str(e))
            signature_image = None

    for page_index, page in enumerate(reader.pages):
        page_width = float(page.mediabox.width)
        page_height = float(page.mediabox.height)

        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=(page_width, page_height))

        for loc in d.get("sign_locations", []):
            assigned_email = (loc.get("recipientEmail") or loc.get("recipient_email") or "").lower().strip()

            if assigned_email and assigned_email != recipient.get("email", "").lower().strip():
                continue

            loc_page = int(loc.get("page", 1)) - 1

            if loc_page != page_index:
                continue

            field_type = loc.get("type", "signature")

            x_percent = float(loc.get("x", 0))
            y_percent = float(loc.get("y", 0))

            x = (x_percent / 100) * page_width
            y_from_top = (y_percent / 100) * page_height

            width_percent = float(loc.get("widthPercent", 0) or 0)
            height_percent = float(loc.get("heightPercent", 0) or 0)

            if width_percent > 0:
                width = (width_percent / 100) * page_width
            else:
                width = float(loc.get("width", 160))

            if height_percent > 0:
                height = (height_percent / 100) * page_height
            else:
                height = float(loc.get("height", 48))

            y = page_height - y_from_top - height

            if field_type == "datetime":
                c.setFillColorRGB(0, 0, 0)
                c.setFont("Helvetica", 10)
                c.drawString(x, y + (height / 2), signed_at_text)

            elif field_type == "signature":
                if signature_image:
                    c.drawImage(
                        signature_image,
                        x,
                        y,
                        width=width,
                        height=height,
                        preserveAspectRatio=True,
                        mask="auto"
                    )
                else:
                    c.setFillColorRGB(0, 0, 0)
                    selected_font = get_pdf_signature_font(signature_font)
                    c.setFont(
                        selected_font,
                        22 if selected_font != "Helvetica-Oblique" else 18
                    )
                    c.drawString(x, y + (height / 2), signature_text)

        c.save()
        packet.seek(0)

        overlay_pdf = PdfReader(packet)

        if len(overlay_pdf.pages) > 0:
            page.merge_page(overlay_pdf.pages[0])

        writer.add_page(page)

    output = io.BytesIO()
    writer.write(output)
    output.seek(0)

    safe_email = recipient["email"].replace("@", "_").replace(".", "_")
    signed_blob_path = f"documents/{doc_id}/signed/{safe_email}.pdf"
    signed_blob = bucket.blob(signed_blob_path)
    signed_blob.upload_from_file(output, content_type="application/pdf")

    try:
        signed_blob.make_public()
        return {
            "url": signed_blob.public_url,
            "path": signed_blob_path
        }
    except Exception as e:
        print("SIGNED PDF MAKE PUBLIC ERROR:", str(e))
        return {"url": "", "path": signed_blob_path}

# ─── Signing Routes ───────────────────────────────────────────────────────────

@app.route("/api/sign/<doc_id>/<token>", methods=["GET"])
def get_sign_info(doc_id, token):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        recipient = next(
            (r for r in d.get("recipients", []) if r.get("token") == token),
            None
        )

        if not recipient:
            return jsonify({"error": "Invalid link"}), 403

        signer_email = recipient.get("email", "").lower().strip()
        signer_locations = [
            loc for loc in d.get("sign_locations", [])
            if (loc.get("recipientEmail") or loc.get("recipient_email") or "").lower().strip() == signer_email
        ]

        return jsonify({
            "document_id": doc_id,
            "title": d.get("title", ""),
            "pdf_url": d.get("pdf_url", ""),
            "preview_url": f"http://localhost:5000/api/documents/{doc_id}/preview",
            "sign_locations": signer_locations,
            "recipient_email": recipient.get("email", ""),
            "recipient_name": recipient.get("name", ""),
            "status": recipient.get("status", ""),
            "message": d.get("message", "")
        }), 200

    except Exception as e:
        print("GET SIGN INFO ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route("/api/sign/<doc_id>/<token>/page-count", methods=["GET"])
def get_sign_page_count(doc_id, token):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        recipient = next(
            (r for r in d.get("recipients", []) if r.get("token") == token),
            None
        )

        if not recipient:
            return jsonify({"error": "Invalid link"}), 403

        blob = bucket.blob(f"documents/{doc_id}/original.pdf")

        if not blob.exists():
            return jsonify({"error": "PDF file not found in Firebase Storage"}), 404

        pdf_bytes = blob.download_as_bytes()
        reader = PdfReader(io.BytesIO(pdf_bytes))

        return jsonify({"pages": len(reader.pages)}), 200

    except Exception as e:
        print("SIGN PAGE COUNT ERROR:", str(e))
        return jsonify({"error": "Failed to read PDF page count"}), 500

@app.route("/api/sign/<doc_id>/<token>", methods=["POST"])
def submit_signature(doc_id, token):
    try:
        doc_ref = db.collection("documents").document(doc_id)
        doc = doc_ref.get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        recipient = next(
            (r for r in d.get("recipients", []) if r.get("token") == token),
            None
        )

        if not recipient:
            return jsonify({"error": "Invalid link"}), 403

        if recipient.get("status") == "signed":
            return jsonify({"error": "Already signed"}), 400

        data = request.json or {}

        signature_text = data.get("signature_text", "").strip()
        signature_font = data.get("signature_font", "Dancing Script")
        signature_image_b64 = data.get("signature_image", "")

        if not signature_text and not signature_image_b64:
            return jsonify({"error": "Signature is required"}), 400

        signer_locations = [
            loc for loc in d.get("sign_locations", [])
            if (loc.get("recipientEmail") or loc.get("recipient_email") or "").lower().strip() == recipient.get("email", "").lower().strip()
        ]

        if not signer_locations:
            return jsonify({"error": "No fields are assigned to this signer"}), 400

        signed_pdf_result = create_signed_pdf(
            doc_id=doc_id,
            d=d,
            recipient=recipient,
            signature_text=signature_text,
            signature_font=signature_font,
            signature_image_b64=signature_image_b64
        )

        signed_pdf_url = signed_pdf_result.get("url", "")
        signed_pdf_path = signed_pdf_result.get("path", "")

        sig_id = str(uuid.uuid4())

        db.collection("signatures").document(sig_id).set({
            "id": sig_id,
            "document_id": doc_id,
            "recipient_email": recipient["email"],
            "signature_text": signature_text,
            "signature_font": signature_font,
            "signature_image": signature_image_b64[:500] if signature_image_b64 else "",
            "signed_pdf_url": signed_pdf_url,
            "signed_at": firestore.SERVER_TIMESTAMP
        })

        updated_recipients = []

        for r in d.get("recipients", []):
            if r.get("token") == token:
                r["status"] = "signed"
                r["signed_at"] = datetime.datetime.utcnow().isoformat()
                r["signed_pdf_url"] = signed_pdf_url
                r["signed_pdf_path"] = signed_pdf_path

            updated_recipients.append(r)

        all_signed = all(r.get("status") == "signed" for r in updated_recipients)

        doc_ref.update({
            "recipients": updated_recipients,
            "status": "completed" if all_signed else "partial",
            "latest_signed_pdf_url": signed_pdf_url,
            "latest_signed_pdf_path": signed_pdf_path,
            "updated_at": firestore.SERVER_TIMESTAMP
        })

        log_activity(
            doc_id,
            d.get("sender_id"),
            "document_signed",
            f"Signed by {recipient['email']}"
        )

        return jsonify({
            "success": True,
            "all_signed": all_signed,
            "signed_pdf_url": signed_pdf_url
        }), 200

    except Exception as e:
        print("SUBMIT SIGNATURE ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route("/api/sign/<doc_id>/<token>/download", methods=["GET"])
def download_signed(doc_id, token):
    try:
        doc = db.collection("documents").document(doc_id).get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        d = doc.to_dict()

        recipient = next(
            (r for r in d.get("recipients", []) if r.get("token") == token),
            None
        )

        if not recipient or recipient.get("status") != "signed":
            return jsonify({"error": "Not signed yet"}), 403

        sig_docs = (
            db.collection("signatures")
            .where("document_id", "==", doc_id)
            .where("recipient_email", "==", recipient["email"])
            .limit(1)
            .get()
        )

        sig = sig_docs[0].to_dict() if sig_docs else {}
        signed_pdf_url = d.get("latest_signed_pdf_url") or sig.get("signed_pdf_url") or recipient.get("signed_pdf_url")

        if not signed_pdf_url:
            return jsonify({
                "error": "Signed PDF was not generated. Please sign the document again."
            }), 404

        return jsonify({
            "pdf_url": signed_pdf_url,
            "preview_url": signed_pdf_url,
            "signature_text": sig.get("signature_text", ""),
            "signed_at": recipient.get("signed_at", "")
        }), 200

    except Exception as e:
        print("DOWNLOAD SIGNED ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


# ─── Email Builder ────────────────────────────────────────────────────────────

def _build_email_html(sender_name, doc_title, message, sign_url, recipient_name):
    msg_section = ""

    if message:
        msg_section = f"""
        <p style="background:#f0f4ff;border-left:4px solid #4F46E5;padding:12px 16px;border-radius:4px;color:#374151;font-style:italic;">
          {message}
        </p>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8f9fa;margin:0;padding:40px 20px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#4F46E5,#7C3AED);padding:40px 32px;text-align:center;">
      <h1 style="color:#fff;margin:0;font-size:28px;font-weight:700;letter-spacing:-0.5px;">SignPrime</h1>
      <p style="color:rgba(255,255,255,0.8);margin:8px 0 0;">Electronic Document Signing</p>
    </div>

    <div style="padding:40px 32px;">
      <p style="color:#374151;font-size:16px;margin:0 0 8px;">Hello {recipient_name},</p>

      <p style="color:#6B7280;font-size:15px;line-height:1.6;margin:0 0 24px;">
        <strong style="color:#111827;">{sender_name}</strong> has requested your signature on the document:
      </p>

      <div style="background:#f9fafb;border:1px solid #E5E7EB;border-radius:8px;padding:16px 20px;margin:0 0 24px;">
        <p style="margin:0;font-size:16px;font-weight:600;color:#111827;">📄 {doc_title}</p>
      </div>

      {msg_section}

      <div style="text-align:center;margin:32px 0;">
        <a href="{sign_url}" style="background:linear-gradient(135deg,#4F46E5,#7C3AED);color:#fff;text-decoration:none;padding:16px 40px;border-radius:50px;font-size:16px;font-weight:600;display:inline-block;box-shadow:0 4px 16px rgba(79,70,229,0.4);">
          ✍️ Sign Document
        </a>
      </div>

      <p style="color:#9CA3AF;font-size:13px;text-align:center;margin:0;">
        This link is unique to you. Please do not share it.
      </p>
    </div>

    <div style="background:#f9fafb;padding:20px 32px;border-top:1px solid #E5E7EB;text-align:center;">
      <p style="color:#9CA3AF;font-size:12px;margin:0;">
        Powered by SignPrime · Secure Electronic Signatures
      </p>
    </div>
  </div>
</body>
</html>
"""

import os
PORT = int(os.getenv('PORT', 5000))
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
