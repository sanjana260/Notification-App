from flask import current_app as app
from flask import render_template,redirect,request,send_from_directory
from flask_login import login_user,LoginManager,login_required,logout_user,current_user
from werkzeug.utils import secure_filename
from application.models import Cases,Messages, Documents,User
from sqlalchemy import or_
from application.database import db
from flask_bcrypt import Bcrypt
from flask_mail import Mail,Message
import os
import numpy as np
import smtplib,ssl
import pandas as pd
import logging

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"
bcrypt = Bcrypt(app)
mail = Mail(app)
basedir = os.path.abspath(os.path.dirname(__file__))
dir = os.path.dirname(basedir)
# logging.basicConfig(level='WARNING', filemode='a', format='%(asctime)s: %(levelname)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
logger = logging.getLogger(__name__)
handler = logging.FileHandler('test.log')
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel('INFO')

ALLOWED_EXTENSIONS = {'pdf'}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/user2",methods = ['GET'])
def user2():
    return render_template('user2.html')

@app.route("/",methods=["Get"])
@login_required
def home():
    role = current_user.Role
    return redirect("/"+str(role))

@app.route("/login",methods=["GET","POST"])
def login():
    if(current_user.is_authenticated):
        return redirect("/")
    if request.method=='POST':
        Username = request.form.get('Username')
        Password= request.form.get('Password')

        user = User.query.filter(User.Username == Username).one()
        if(not user):
            return render_template('login.html',message='Username does not exist')
        if not bcrypt.check_password_hash(user.Password,Password):
            return render_template('login.html',message = 'Password incorrect')
        login_user(user)
        logger.info(f"{current_user.Username} ({current_user.Role} : {current_user.id}) has logged in")
        return redirect("/")
    return render_template('login.html')

@app.route("/logout",methods=["GET"])
@login_required
def logout():
    logger.info(f"{current_user.Username} ({current_user.Role} : {current_user.id}) logged out")
    logout_user()
    return redirect("/login")

@app.route("/send_mail",methods=["GET"])
@login_required
def send_mail():
    msg = Message(
        'Hello',
        sender='testsender135@gmail.com',
        recipients=['sanjanamohan260@gmail.com']
    )
    msg.body = 'Hello this is from Flask mail'
    mail.send(msg)
    return redirect('/login')

@app.route("/add_user",methods=["GET","POST"])
def add_user():
    if(request.method=="POST"):
        Username = request.form.get("Username")
        Email = request.form.get("Email")
        Password = request.form.get("Password")
        Password = bcrypt.generate_password_hash(Password).decode('utf-8')
        Type = request.form.get("user_type")
        Verifier_id = int(request.form.get("Verifier_id"))
        #Checking Username and Email
        Existing_user = User.query.filter(or_(User.Email==Email , User.Username==Username)).all()
        if(Existing_user):
            return render_template('add_user.html',message="Username or Email already exists")

        # Checking Verifier ID
        if(Type=="supervisor" and Verifier_id!=-1) or (Type =='health_check_team' and Verifier_id!=-1):
            return render_template('add_user.html',message = 'Invalid Verifier ID')
        elif(Type=="supervisor" and Verifier_id==-1) or (Type =='health_check_team' and Verifier_id==-1):
            pass
        else:
            Verifier = User.query.get(Verifier_id)
            if not Verifier:
                return render_template('add_user.html',message = 'Invalid Verifier ID')
            Verifier_role = Verifier.Role
            if(Type=='user' and Verifier_role!='verifier') or (Type=='verifier' and Verifier_role!='supervisor'):
                return render_template('add_user.html',message = 'Invalid Verifier ID')
        
        new_user = User(Username = Username, Email = Email, Password = Password,Role=Type,Verifier_id=Verifier_id)
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"New User {new_user.Username} ({new_user.Role} : {new_user.id}) has been created with email {new_user.Email} and supervisor (or verifier) ID {new_user.Verifier_id}")
        return redirect("/login")
    return render_template('add_user.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/user",methods = ["GET","POST"])
@login_required
def userpage():
    if(current_user.Role != "user"):
        return redirect("/")
    cases = Cases.query.filter(Cases.User_id == current_user.id).all()
    verified = len(list(filter(lambda x : x.Status == "Verified",cases)))
    rejected = len(list(filter(lambda x : x.Status == "Rejected",cases)))
    return render_template("user2.html",cases = cases,verified = verified,rejected = rejected)

@app.route("/profile",methods = ["GET","POST"])
@login_required
def profile():
    return render_template("profile.html")

@app.route("/verifier",methods = ["GET","POST"])
@login_required
def verifiers():
    if(current_user.Role != "verifier"):
        return redirect('/')
    user_list = User.query.filter(User.Verifier_id==current_user.id).all()
    user_id_list = list(map(lambda x: x.id, user_list))
    cases = Cases.query.filter(Cases.User_id.in_(user_id_list)).all()
    verified = len(list(filter(lambda x : x.Status == "Verified",cases)))
    rejected = len(list(filter(lambda x : x.Status == "Rejected",cases)))
    return render_template("user2.html",cases = cases,verified = verified,rejected = rejected)

@app.route("/supervisor",methods = ["GET","POST"])
@login_required
def supervisors():
    if(current_user.Role != 'supervisor'):
        return redirect('/')
    user_id = current_user.id
    verifier_list = User.query.filter(User.Verifier_id==user_id).all()
    verifier_id_list = map(lambda x:x.id, verifier_list)
    user_list = User.query.filter(User.Verifier_id.in_(verifier_id_list)).all()
    user_id_list = list(map(lambda x: int(x.id), user_list))
    cases = Cases.query.filter(Cases.User_id.in_(user_id_list)).all()
    verified = len(list(filter(lambda x : x.Status == "Verified",cases)))
    rejected = len(list(filter(lambda x : x.Status == "Rejected",cases)))
    return render_template("user2.html",cases = cases,verified = verified,rejected = rejected)

@app.route("/health_check_team",methods = ["GET","POST"])
@login_required
def health_check():
    message = ''
    if(current_user.Role != "health_check_team"):
        return redirect('/')
    if(request.method == 'POST'):
        file = request.files['exception_list']
        data = pd.read_excel(file)
        failure = 0
        for index,row in data.iterrows():
            if(row["Raise exception"]=='Yes'):
                user = User.query.get(row["User ID"])
                if(user.Role !='user' ):
                    failure += 1
                    continue
                new_case = Cases(Status = 'Pending',Comment = row["Exception Description"],User_id = row["User ID"], Verifier_id = user.Verifier_id)
                db.session.add(new_case)
                db.session.commit()
                logger.info(f"User {current_user.id} uploaded case no. {new_case.id} with User ID: {new_case.User_id} and Verifier ID: {new_case.Verifier_id}.")
        success = data.shape[0]- failure
        if(failure==0):
            message = "Success! " + str(success) + " entries were pushed"
        elif(success==0):
            message = "Operation failed. "+ str(failure)+" entries were not pushed due to invalid User ID"
        else:
            message = "Success! " + str(success) + " entries were pushed. " + str(failure) + " entries were not pushed due to invalid User ID."
    return render_template("health_check_team.html",message = message)

@app.route("/upload_file/<int:case_id>",methods = ["POST"])
@login_required
def upload_file(case_id):
    file = request.files['file']
    case = Cases.query.get(int(case_id))
    if(current_user.id!=case.User_id) and (current_user.id!=case.Verifier_id):
        return redirect('/')
    if not case:
        print("Case not found")
        return redirect('/case/'+str(case_id))
    if (case.Status != 'Pending'):
        print("Case already closed")
        return redirect('/case/'+str(case_id))
    if file.filename == '':
        print("No file")
        return redirect('/case/'+str(case_id))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        document = Documents(Filename = filename, Uploader_id = current_user.id,Case_id = case_id)
        db.session.add(document)
        db.session.commit()
        logger.info(f"File {filename} uploaded regarding case {case_id} by user {current_user.id}")
        return redirect('/case/'+str(case_id))
    return redirect('/case/'+str(case_id))

@app.route('/verify_case/<int:case_id>',methods=["GET"])
@login_required
def verify_case(case_id):
    case = Cases.query.get(int(case_id))
    if not case:
        print("Case not found")
        return redirect('/')
    if not case.Verifier_id == current_user.id:
        return redirect('/')
    case.Status = 'Verified'
    db.session.add(case)
    db.session.commit()
    logger.info(f"Case no. {case_id} verified by verifier {current_user.id}")
    return redirect('/')

@app.route('/reject_case/<int:case_id>',methods=["GET"])
@login_required
def reject_case(case_id):
    case = Cases.query.get(int(case_id))
    if not case:
        print("Case not found")
        return redirect('/')
    if not case.Verifier_id == current_user.id:
        return redirect('/')
    case.Status = 'Rejected'
    db.session.add(case)
    db.session.commit()
    logger.info(f"Case no. {case_id} rejected by verifier {current_user.id}")
    return redirect('/')

@app.route('/download_file/<int:document_id>',methods = ["GET"])
@login_required
def download_file(document_id):
    document = Documents.query.filter(Documents.id==document_id).one()
    case = Cases.query.filter(Cases.id == document.Case_id).one()
    verifier = User.query.get(case.Verifier_id)
    if(current_user.id not in [case.User_id, case.Verifier_id, verifier.Verifier_id]):
        return redirect('/')
    file_name = document.Filename
    logger.info(f"User {current_user.id} ({current_user.Role}) downloaded file \"{file_name}\" regarding case {case.id}")
    return send_from_directory(app.config['UPLOAD_FOLDER'],file_name,as_attachment=True)

@app.route('/case/<int:case_id>',methods = ["GET","POST"])
@login_required
def case(case_id):
    case = Cases.query.get(case_id)
    verifier = User.query.get(case.Verifier_id)
    if(current_user.id not in [case.User_id, case.Verifier_id, verifier.Verifier_id]):
        return redirect('/')
    messages = Messages.query.filter(Messages.Case_id == case_id).all()
    message_senders = [User.query.get(message.Sender_id) for message in messages]
    documents = Documents.query.filter(Documents.Case_id == case_id).all()
    document_senders = [User.query.get(document.Uploader_id) for document in documents]
    return render_template('case.html',case = case,messages = messages,documents = documents,message_senders=message_senders,document_senders=document_senders)

@app.route('/send_message/<int:case_id>',methods = ["POST"])
@login_required
def send_message(case_id):
    if(current_user=={}):
        return redirect('/login')
    content = request.get_json()["Content"]
    case = Cases.query.get(case_id)
    if (case.Status != 'Pending'):
        print("Case already closed")
        return redirect('/case/'+str(case_id))
    verifier = User.query.get(case.Verifier_id)
    if(current_user.id not in [case.User_id, case.Verifier_id, verifier.Verifier_id]):
        return redirect('/')
    new_message = Messages(Content = content, Sender_id = current_user.id, Case_id = case_id)
    db.session.add(new_message)
    db.session.commit()
    logger.info(f"User {current_user.id} sent a message (Message ID: {new_message.id}) regarding case {case_id}")
    return redirect('/case/'+str(case_id))

def send_mail(ids,message):
    port = 465
    smtp_server = "smtp.gmail.com"
    sender_email = "testsender135@gmail.com"
    receiver_email = ids
    password = "Password@135"
    message="""\
    Subject: Hi there


    This message is sent from Python.
    """
    subject = ''
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
    logger.info(f"Sent mail to users {ids} with Subject {subject}")

