#Importing stuff
import csv
from logging import log
from flask import Flask, render_template, redirect, request, jsonify, url_for, session, make_response
from datetime import datetime, timedelta, timezone
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
import os, sys, sqlite3
import webbrowser, threading
from supabase import create_client
from dotenv import load_dotenv
import json
from zoneinfo import ZoneInfo
import csv
import io


#Parses the env file made
load_dotenv()

Supabase_URL = os.getenv("SUPABASE_URL")
Supabase_ServiceKey = os.getenv("SUPABASE_SERVICEKEY")
supabase = create_client(Supabase_URL, Supabase_ServiceKey)
#Establishes the connection but might need to remove service key later

# Need to refine the time ago function, it works for now
def time_ago(timestamp_str):
    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    pakistan_tz = ZoneInfo("Asia/Karachi") 
    timestamp_local = timestamp.astimezone(pakistan_tz)
    now_local = datetime.now(pakistan_tz)
    diff = now_local - timestamp_local 
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return f"{int(seconds)}s ago"
    elif seconds < 3600:
        return f"{int(seconds/60)}m ago"
    elif seconds < 86400:
        return f"{int(seconds/3600)}h ago"
    else:
        return f"{int(seconds/86400)}d ago"

# Used for by-campus logs
def sec_ago(timestamp_str):
    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    now = datetime.now()
    diff = now - timestamp

    seconds = diff.total_seconds()
    return int(seconds)


# Establishing Flask app
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.secret_key = os.getenv("FLASK_SECRET", "dev")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"
app.config["JWT_COOKIE_SECURE"] = False   # True only on HTTPS (Render will handle that)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False


bcrypt = Bcrypt(app)
jwt = JWTManager(app)


#Setting up home page
@app.route("/", methods = ["GET", "POST"])
def home():
    if request.cookies.get("access_token_cookie"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("admin_login"))
    

# Admin login
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Fetch the admin details from table
        result = supabase.table("Admins").select("*").eq("Email", email).execute()
        if not result.data:
            return render_template("admin_login.html", error = "Admin not found")
        
        admin = result.data[0]

        # Check password hash
        if not bcrypt.check_password_hash(admin["Password_Hash"], password):
            return render_template("admin_login.html", error="Invalid password")


        # Create JWT token valid for 15 hour and show the admin's campus infoi
        token = create_access_token(
            identity=email, expires_delta= timedelta(hours=15)
        )

        resp = redirect(url_for("admin_dashboard"))
        resp.set_cookie("access_token_cookie", token, httponly=True)
        return resp
    
    s = url_for("static", filename="logo.png")
    return render_template("admin_login.html", s=s)


# Creates the dashboard which shows by campus logs (and need to add admin name here)
@app.route("/admin/dashboard")
@jwt_required(optional=True)
def admin_dashboard():
    
    email = get_jwt_identity()  # gets 'email'
    if not email:
        return(redirect(url_for("admin_login")))
    
    admin_response = supabase.table("Admins").select("Campus_ID").eq("Email", email).execute()
    if not admin_response:
        return jsonify({"error": "Admin not found"}), 404
    
    # print(admin_response.data) # For debugging  
    
    campus_id = admin_response.data[0]['Campus_ID']

    campus_response = supabase.table("Campus").select("Name").eq("id", campus_id).execute()
    if not campus_response:
        return jsonify({"error": "Campus not found"}), 404
    
    campus_name = campus_response.data[0]["Name"]

    adminname_response = supabase.table("Admins").select("Admin_Name").eq("Email", email).execute()
    admin_name = adminname_response.data[0]["Admin_Name"]
    # Fetch campus logs
    result = supabase.rpc("get_logs_by_campus", {"campus_name": campus_name}).execute()
    logs = result.data or []
    
    message = f"No students from {campus_name} logged in currently." if not logs else None
    for log in logs:
        if log["rawtime"]:
            log["time_ago"] = time_ago(log["rawtime"])
            log["sec_ago"] = sec_ago(log["rawtime"])
    # Need to add duration column in the table

    return render_template("view_logs.html", campus=campus_name, logs=logs, message=message, admin_name=admin_name)


#Logging-in
@app.route("/admin/add_student", methods = ["GET", "POST"])
@jwt_required()
def add_student():
    email = get_jwt_identity()
    
    if not email:
        return(redirect(url_for("admin_login")))
    
    # Gets admin's campus ID
    admin_response = supabase.table("Admins").select("Campus_ID").eq("Email", email).execute()
    if not admin_response:
        return jsonify({"error": "Admin not found"}), 404
    campus_id = admin_response.data[0]["Campus_ID"]
    campus = supabase.table("Campus").select("Name").eq("id", campus_id).execute()
    locale = campus.data[0]["Name"]

    # Gets admin's ID
    adminid_response = supabase.table("Admins").select("id").eq("Email", email).execute()
    admin_id = adminid_response.data[0]["id"]
    
    # Handles the logging in and out
    if request.method == "POST":        
        rfid = request.form.get("rfid")

        campus_info = supabase.table("Students").select("Campus_id").eq("RFID", rfid).execute()
        try:
            
            home_campus = campus_info.data[0]["Campus_id"]
        except:
            # If RFID not found need to give option to add student
            message = "RFID not found"
            result = supabase.rpc("get_logged_in").execute()
            tots = supabase.table("Logs").select("*", count="exact").is_("check_out", "null").execute()
            tot = tots.count
            logs = result.data or []
            for log in logs:
                if log["rawtime"]:
                    log["time_ago"] = time_ago(log["rawtime"])
            return render_template("login.html", logs=logs, message=message, locale=locale, tot=tot)
        
        campus = supabase.table("Campus").select("Name").eq("id", home_campus).execute()
        
        response = supabase.rpc("log_in_or_out", {
            "rfid_input": int(rfid),
            "campus_input": home_campus,
            "locale": locale,
            "admin_id": admin_id
        }).execute()
        
        
        


        action = response.data if response.data else "Action failed"
        message = action
        return redirect(url_for("add_student"))
    else:
        message = None

    result = supabase.rpc("get_logged_in").execute()
    tots = supabase.table("Logs").select("*", count="exact").is_("check_out", "null").execute()
    tot = tots.count
    logs = result.data or []
    for log in logs:
        if log["rawtime"]:
            log["time_ago"] = time_ago(log["rawtime"])

    return render_template("login.html", logs=logs, message=message, locale=locale, tot=tot)
    

#Viewing the sum hours

@app.route("/admin/summary")
@jwt_required()
def summary():

    result = supabase.rpc("get_total_hours").execute()
    rows = result.data if result.data else []

    return render_template("SumHours.html", rows=rows)

@app.route("/logout")
def logout():
    resp = redirect(url_for("admin_login"))
    resp.delete_cookie("access_token_cookie")
    return resp

@app.route("/export_logs")
@jwt_required()
def export_logs():

    email = get_jwt_identity()

    admin = supabase.table("Admins").select("Role").eq("Email", email).execute()
    # if admin.data[0]["Role"] != "Super":
    #     return jsonify({"error": "Unauthorized"}), 403
    result = supabase.rpc("export_logs").execute()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "RFID", "Name", "Campus", "Event", "Check In", "Check Out", "Approved", "Logged In By", "Logged Out By", "Duration (hours)"
    ])
    for res in result.data:
        writer.writerow([ res["RFID"], res["Name"], res["Campus"], res["Event"], res["Check_In"], res["Check_Out"], res["Approved"], res["Logged_In_By"], res["Logged_Out_By"], res["Duration_Hours"] ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=logs.csv"
    response.headers["Content-type"] = "text/csv"
    return response

#Creating a page for the scanner
@app.route("/scanner", methods=["GET", "POST"])
@jwt_required()
def scanner():
    email = get_jwt_identity()
    if not email:
        return redirect(url_for("admin_login"))

    admin = supabase.table("Admins") \
        .select("id, Role, Campus_ID") \
        .eq("Email", email) \
        .single() \
        .execute()

    if not admin.data or admin.data["Role"] not in ["Scanner", "Super", "Admin"]:
        return redirect(url_for("admin_login"))

    campus = supabase.table("Campus") \
        .select("Name") \
        .eq("id", admin.data["Campus_ID"]) \
        .single() \
        .execute()

    locale = campus.data["Name"]
    message = None
    status = None
    print("Working")
    print(request.method)
    if request.method == "POST":
        rfid = request.form.get("rfid", "").strip()

        print(f"RFID received: {rfid}")
        if not rfid.isdigit():
            return render_template(
                "scanner.html",
                message="Invalid RFID",
                status="error"
            )
        try:
            student = supabase.table("Students") \
                .select("Campus_id") \
                .eq("RFID", int(rfid)) \
                .single() \
                .execute()
        except:
        
            return render_template(
                "scanner.html",
                message="Unknown RFID",
                status="error"
            )

        print(f"Student Campus ID: {student.data['Campus_id']}")
        response = supabase.rpc(
            "log_in_or_out",
            {
                "rfid_input": int(rfid),
                "campus_input": student.data["Campus_id"],
                "locale": locale,
                "admin_id": admin.data["id"]
            }
        ).execute()
        print(f"RPC Response: {response.data}")
        if response.data:
            message = response.data
            status = "success"
        else:
            message = "Scan failed"
            status = "error"
        print(f"Final Message: {message}, Status: {status}")

    return render_template(
        "scanner.html",
        message=message,
        status=status
    )
    

def open_browser():
    webbrowser.open("http://127.0.0.1:5000/admin/login")
threading.Timer(1.0, open_browser).start()





if __name__ == "__main__":

    app.run(debug=True)
