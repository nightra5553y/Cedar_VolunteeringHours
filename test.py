#Importing stuff
from flask import Flask, render_template, redirect, request, jsonify, url_for, session
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
import os, sys, sqlite3
import webbrowser, threading
from supabase import create_client
from dotenv import load_dotenv
import json

#Parses the env file made
load_dotenv()

Supabase_URL = os.getenv("SUPABASE_URL")
Supabase_ServiceKey = os.getenv("SUPABASE_SERVICEKEY")
#Access the database made in supabase

supabase = create_client(Supabase_URL, Supabase_ServiceKey)


#Creating the actual web
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")

app.secret_key = os.getenv("FLASK_SECRET", "dev")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"
app.config["JWT_COOKIE_SECURE"] = False   # True only on HTTPS (Render will handle that)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
locale = []
#Setting up home page
@app.route("/", methods = ["GET", "POST"])
def home():
    if request.cookies.get("access_token_cookie"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("admin_login"))
    

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Fetch the admin dets from table
        result = supabase.table("Admins").select("*").eq("Email", email).execute()
        if not result.data:
            return render_template("admin_login.html", error = "Admin not found")
        
        admin = result.data[0]

        
        # Check password hash
        if not bcrypt.check_password_hash(admin["Password_Hash"], password):
            return render_template("admin_login.html", error="Invalid password")


        # Create JWT token valid for 1 hour and show the admin's campus infoi
        token = create_access_token(
            identity=email, expires_delta= timedelta(hours=1)
        )

        resp = redirect(url_for("admin_dashboard"))
        resp.set_cookie("access_token_cookie", token, httponly=True)
        return resp
    return render_template("admin_login.html")


@app.route("/admin/dashboard")
@jwt_required(optional=True)
def admin_dashboard():
    email = get_jwt_identity()  # gets 'email'
    if not email:
        return(redirect(url_for("admin_login")))
    
    admin_response = supabase.table("Admins").select("Campus_ID").eq("Email", email).execute()
    if not admin_response:
        return jsonify({"error": "Admin not found"}), 404
    
    print(admin_response.data)  
    
    campus_id = admin_response.data[0]['Campus_ID']

    campus_response = supabase.table("Campus").select("Name").eq("id", campus_id).execute()
    if not campus_response:
        return jsonify({"error": "Campus not found"}), 404
    
    campus_name = campus_response.data[0]["Name"]


    # Fetch campus logs
    result = supabase.rpc("get_logs_by_campus", {"campus_name": campus_name}).execute()
    logs = result.data or []
    
    message = f"No students from {campus_name} logged in currently." if not logs else None
    
    return render_template("view_logs.html", campus=campus_name, logs=logs, message=message)


#Logging-in
@app.route("/admin/add_student", methods = ["GET", "POST"])
@jwt_required()
def add_student():
    email = get_jwt_identity()
    if not email:
        return(redirect(url_for("admin_login")))
    
    admin_response = supabase.table("Admins").select("Campus_ID").eq("Email", email).execute()
    if not admin_response:
        return jsonify({"error": "Admin not found"}), 404
    
    campus_id = admin_response.data[0]["Campus_ID"]
    campus = supabase.table("Campus").select("Name").eq("id", campus_id).execute()
    locale = campus.data[0]["Name"]
    if request.method == "POST":        
        rfid = request.form.get("rfid")

        campus_info = supabase.table("Students").select("Campus_id").eq("RFID", rfid).execute()
        home_campus = campus_info.data[0]["Campus_id"]
        campus = supabase.table("Campus").select("Name").eq("id", home_campus).execute()
        
        response = supabase.rpc("log_in_or_out", {
            "rfid_input": int(rfid),
            "campus_input": home_campus
        }).execute()
        

        


        action = response.data if response.data else "Action failed"
        message = action
    else:
        message = None

    result = supabase.rpc("get_logged_in").execute()
    logs = result.data or []
    

    
    

    return render_template("login.html", logs=logs, message=message, locale=locale)
    

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


def open_browser():
    webbrowser.open("http://127.0.0.1:5000/admin/login")
threading.Timer(1.0, open_browser).start()




if __name__ == "__main__":

    app.run(debug=True)
