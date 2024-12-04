import os
import pathlib
from os import abort

import requests

from app import app, db
import datetime
from flask_mail import Mail, Message
import random, string
from flask import render_template, request, redirect, url_for, session, jsonify
from app.forms import (
    CancelMembership,
    LoginForm,
    CreateAccountForm,
    ChangePassword,
    ForgotPassword,
    SelectUser,
)
from flask_login import (
    login_user,
    login_required,
    logout_user,
    current_user,
    LoginManager,
)
from app.models import (
    Account,
    Booking,
    Address,
    Facility,
    Activity,
    ActivityLocation,
    AccountType,
    Booking,
    Membership,
    MembershipPrices,
    Receipt,
)
from app.util import (
    numberToDay,
    numericToTime,
    numericToTuple,
    timeToNumeric,
    dateSuffix,
)
import logging, datetime
from sqlalchemy import or_, and_
from decimal import Decimal, ROUND_UP, ROUND_DOWN
from uuid import uuid4
from pathlib import Path

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "/"

# Used for storing sensitive info, like payment session IDs.
localSession = {}

YOUR_DOMAIN = "https://localhost:5000"

import stripe

# Google OAuth
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token

# Facebook OAuth
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
facebook_bp = make_facebook_blueprint(
    client_id='944779146703599',
    client_secret='26698767cda1fe14f5167226f5e88247',
    scope='email, public_profile, user_birthday,user_hometown',
)
app.register_blueprint(facebook_bp, url_prefix='/login/facebook')

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

stripe.api_key = "sk_test_51MlDPbCvuWQSx8eZCIUKHwnf0PmQqe4Nk2KNdZkvBHUsnFNYSxA8Kb3e4Pbm7Hg2qCFYjs909XCAypquv7DLZ24F00cdEg4x2Y"

GOOGLE_CLIENT_ID = (
    "630445047989-2m83hp7thu0buftqgfp974k21f36qinl.apps.googleusercontent.com"
)
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

app.config.update(
    dict(
        DEBUG=True,
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USE_SSL=False,
        MAIL_USERNAME="robotmail2000",
        MAIL_PASSWORD="ilyghdxhmfgcmggy",
    )
)

mail = Mail(app)


# Function to check account type
def AccountTypeCheck():
    if "accountType" in session:
        if session["accountType"] == "Manager":
            return "Manager"
        elif session["accountType"] == "Employee":
            return "Employee"
        elif session["accountType"] == "User":
            return "User"
        else:
            return "None"
    else:
        session["accountType"] = "None"
        return "None"


@login_manager.user_loader
def load_user(user_id):
    app.logger.info("Load User")
    return Account.query.get(user_id)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token, request=token_request, audience=GOOGLE_CLIENT_ID
    )

    # get's the user from the database
    user = (
        db.session.query(Account).filter(Account.email == id_info.get("email")).first()
    )

    # if the user is in the database, login in.
    if user != None:
        login_user(user)
        session["google_id"] = user.id
        return redirect("/")
    else:
        logging.warning(f"Account doesn't exist for {id_info.get('email')}")
        return redirect("/login")
    # print(user.email)


@app.route("/login_with_google", methods=["GET", "POST"])
def login_with_google():
    authorisation_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(authorisation_url)

@app.route('/login_with_facebook')
def login_with_facebook():
    if not facebook.authorized:
        return redirect(url_for('facebook.login', next=request.url))
    resp = facebook.get('/me?fields=id')
    if resp.ok:
        user_data = resp.json()
        user_id = user_data.get('id')
        if not user_id:
            # flash('Email address not available from Facebook.')
            session["alert"] = {"color": "danger", "start": "Login Failed", "msg": "Facebook ID not available from Facebook."}
            return redirect(url_for('loginPage'))
        user = db.session.query(Account).filter(Account.facebookid == user_id).first()
        if user:
            login_user(user)
            # flash('Logged in successfully.')
            return redirect(url_for('HomePage'))
        else:
            # flash('Facebook Account is not linked to an Account.')
            session["alert"] = {"color": "danger", "start": "Login Failed", "msg": "Facebook Account is not linked to an Account"}
            return redirect(url_for('loginPage'))
    session["alert"] = {"color": "danger", "start": "Login Failed", "msg": "Facebook Login Failed"}
    return redirect(url_for('loginPage'))

@app.route("/create_account_with_facebook")
def create_account_with_facebook():
    if not facebook.authorized:
        return redirect(url_for('facebook.login', next=request.url))
    resp = facebook.get('/me?fields=id,email,birthday,first_name,last_name')
    if resp.ok:
        user_data = resp.json()
        user_email = user_data.get('email')
        user_id = user_data.get('id')
        user_birthday = user_data.get('birthday')
        user_firstname = user_data.get('first_name'),
        user_lastname = user_data.get('last_name'),
        #Convert tuple to string
        user_firstname = ''.join(user_firstname)
        user_lastname = ''.join(user_lastname)


        
        #Convert birthday string to datetime
        user_birthday = datetime.datetime.strptime(user_birthday, '%m/%d/%Y')
        if not user_email:
            # flash('Email address not available from Facebook.')
            session["alert"] = {"color": "danger", "start": "Login Failed", "msg": "Email address not available from Facebook."}
            return redirect(url_for('loginPage'))
        user = db.session.query(Account).filter(Account.facebookid == user_id).first()
        if user:
            login_user(user)
            session["alert"] = {"color": "success", "start": "Logged In", "msg": "Logged in successfully."}
            return redirect(url_for('HomePage'))
        else:
            #Create new account
            new_account = Account(
                username="FacebookUser" + user_id,
                firstname = user_firstname,
                surname = user_lastname,
                email=user_email,
                password="", #No password for Facebook accounts
                facebookid=user_id,
                dob=user_birthday,
            )
            db.session.add(new_account)
            db.session.commit()
            #Login
            login_user(new_account)
            session["alert"] = {"color": "success", "start": "Account Created", "msg": "Account created successfully."}
            return redirect(url_for('HomePage'))
    session["alert"] = {"color": "danger", "start": "Login Failed", "msg": "Failed to get user info from Facebook."}
    return redirect(url_for('loginPage'))

@app.route("/link_account_with_facebook")
def link_account_with_facebook():
    if(current_user.is_authenticated):
        if not facebook.authorized:
            return redirect(url_for('facebook.login', next=request.url))
        resp = facebook.get('/me?fields=id')
        if resp.ok:
            #Get current logged in user
            user = current_user
            user_data = resp.json()
            user_id = user_data.get('id')
            if not user_id:
                # flash('Facebook ID not available from Facebook.')
                session["alert"] = {"color": "danger", "start": "Login Failed", "msg": "Facebook ID not available from Facebook."}
                return redirect(url_for('account_info'))
            user.facebookid = user_id
            db.session.commit()
            # flash('Facebook Account linked successfully.')
            return redirect(url_for('HomePage'))

@app.route("/unlink_account_from_facebook")
def unlink_account_from_facebook():
    if(current_user.is_authenticated):
        user = current_user
        user.facebookid = None
        db.session.commit()
        # flash('Facebook Account unlinked successfully.')
        return redirect(url_for('accountInfo'))




@app.route("/login", methods=["GET", "POST"])
def loginPage():
    form = LoginForm()
    # Redirect if we're already logged in
    if current_user.is_authenticated:
        return redirect("/")

    if request.method != "POST":
        return render_template("login_page.html", form=form)

    if not form.validate_on_submit():
        logging.warning("Login: Invalid form submitted")
        return (
            render_template(
                "login_page.html",
                form=form,
                alert={"color": "danger", "msg": "Invalid form."},
            ),
            500,
        )

    # Read details from form
    username = form.username.data
    password = form.password.data

    user = db.session.query(Account).filter(Account.username == username).first()
    if user and user.check_password(password):
        login_user(user)
        session["google_id"] = user.id  # setting the google login id.

        logging.info(f"User {user.username} logged in")
        # Session variable to determine account type
        if user.accountType == AccountType.Manager:
            session["accountType"] = "Manager"
        elif user.accountType == AccountType.Employee:
            session["accountType"] = "Employee"
        else:
            session["accountType"] = "User"

        if user.generatedPassword:
            return redirect("/change_password")
        return redirect("/")
    logging.warning(f"Login: Username/Password was invalid")
    return render_template(
        "login_page.html",
        form=form,
        alert={"msg": "Username/Password invalid", "color": "danger"},
    )


@app.route("/create_account", methods=["GET", "POST"])
def createAccountPage():
    form = CreateAccountForm()
    # Redirect if we're already logged in
    if current_user.is_authenticated:
        return redirect("/")

    if request.method != "POST":
        return render_template("create_account.html", form=form)

    if not form.validate_on_submit():
        logging.warning("Signup: Invalid form submitted")
        return (
            render_template(
                "create_account.html",
                form=form,
                alert={"color": "danger", "msg": "Invalid form."},
            ),
            500,
        )

    username = form.username.data
    password = form.password.data
    email = form.email.data
    first_name = form.first_name.data
    last_name = form.last_name.data
    post_code = form.post_code.data
    date_of_birth = form.date_of_birth.data

    address_line_1 = form.AddressLine1.data
    address_line_2 = form.AddressLine2.data
    address_line_3 = form.AddressLine3.data
    city = form.City.data
    country = form.Country.data
    phone_number = form.Phone_Number.data

    user = db.session.query(Account).filter(Account.username == username).first()
    if user:
        return render_template(
            "create_account.html",
            form=form,
            alert={
                "msg": "Username/Password taken, please try another",
                "color": "danger",
            },
        )
    user = db.session.query(Account).filter(Account.email == email).first()
    if user:
        return render_template(
            "create_account.html",
            form=form,
            alert={"msg": "Email address taken, please try another", "color": "danger"},
        )

    new_user = Account(
        username=username,
        email=email,
        firstname=first_name,
        surname=last_name,
        dob=date_of_birth,
    )

    new_user.set_password(password)
    # Commit user so we can get its ID to put in the address.
    with app.app_context():
        db.session.add(new_user)
        db.session.flush()

        # address = Address(accountId=new_user.id, postcode=post_code)
        address = Address(
            accountId=new_user.id,
            line1=address_line_1,
            line2=address_line_2,
            line3=address_line_3,
            city=city,
            country=country,
            postcode=post_code,
            phone=phone_number,
        )
        db.session.add(address)

        db.session.commit()

    # Render page with success message, then redirect to login after 2s (2000ms).
    return render_template(
        "create_account.html",
        form=form,
        alert={"start": "Success", "msg": "Account created.", "color": "success"},
        redirect={"url": "/login", "timeout": "2000"},
    )


@app.route("/logout", methods=["GET", "POST"])
@login_required
def Logout():
    logout_user()
    session["accountType"] = "None"
    return redirect(url_for("HomePage"))


@app.route("/", methods=["GET", "POST"])
def HomePage():
    if current_user.is_authenticated:
        checkMembership(current_user.id)
        membership = (
            db.session.query(Membership)
            .filter(Membership.accountId == current_user.id)
            .first()
        )

        # bookings = getBookings(current_user, until=(datetime.datetime.now() + datetime.timedelta(days=7)))
        bookings = getBookings(current_user)

        now = datetime.datetime.now()
        weekStart = now - datetime.timedelta(days=now.weekday())
        weekBookings = getBookings(current_user, fromTime=weekStart, until=now)
        weekBookingCount = len(weekBookings["past"]["activities"]) + len(
            weekBookings["past"]["classes"]
        )

        # Maximum number of activities/classes to show.
        activityCap = 3

        return render_template(
            "home.html",
            upcomingBookings=bookings["upcoming"]["activities"],
            upcomingClasses=bookings["upcoming"]["classes"],
            membership=membership,
            weekBookingCount=weekBookingCount,
            activityCap=activityCap,
        )

    return render_template("home.html")


# All management pages
@app.route("/management", methods=["GET", "POST"])
def Management():
    # Checks if the account is a managers account
    if AccountTypeCheck() == "Manager":
        return render_template("management.html")
    return redirect("/")


@app.route("/manage_prices", methods=["GET", "POST"])
def ManagePrices():
    if AccountTypeCheck() == "Manager":
        allPrices = db.session.query(MembershipPrices).all()
        if request.method == "POST":
            if len(request.form["bronze_price"]) > 0:
                newPrice = "{0:.2f}".format(
                    round(float(request.form["bronze_price"]), 2)
                )
                toChange = (
                    db.session.query(MembershipPrices)
                    .filter(MembershipPrices.name == "Single")
                    .first()
                )
                toChange.price = newPrice
            if len(request.form["gold_price"]) > 0:
                newPrice = "{0:.2f}".format(round(float(request.form["gold_price"]), 2))
                toChange = (
                    db.session.query(MembershipPrices)
                    .filter(MembershipPrices.name == "Month")
                    .first()
                )
                toChange.price = newPrice
            if len(request.form["platinum_price"]) > 0:
                newPrice = "{0:.2f}".format(
                    round(float(request.form["platinum_price"]), 2)
                )
                toChange = (
                    db.session.query(MembershipPrices)
                    .filter(MembershipPrices.name == "Year")
                    .first()
                )
                toChange.price = newPrice

            db.session.commit()
        return render_template("manage_prices.html", prices=allPrices)
    return redirect("/")


@app.route("/manage_activities_facilities", methods=["GET", "POST"])
def ManageActivitiesFacilities():
    if AccountTypeCheck() == "Manager":
        # This happens if they have updated anything
        if request.method == "POST":
            if "function" in request.form:
                toChange = (
                    db.session.query(Facility)
                    .filter(request.form["facilityID"] == Facility.id)
                    .first()
                )
                if request.form["function"] == "updateFacilityName":
                    toChange.name = request.form["facilityName"]
                elif request.form["function"] == "updateFacilityCapacity":
                    toChange.capacity = request.form["facilityCapacity"]
                elif request.form["function"] == "updateFacilityOpen":
                    newTime = timeToNumeric(request.form["time"])
                    toChange.opens = newTime
                elif request.form["function"] == "updateFacilityClose":
                    newTime = timeToNumeric(request.form["time"])
                    toChange.closes = newTime
                elif request.form["function"] == "updateFacilityActivities":
                    activity = (
                        db.session.query(Activity)
                        .filter(request.form["activityName"] == Activity.name)
                        .first()
                    )
                    activity.name = request.form["activityNew"]
            else:
                # Remove all existing function tags from session
                session.pop("accActToFac", None)
                session.pop("editActivityName", None)
                session.pop("editFacilityID", None)
                for key in request.form:
                    if key.startswith("delete_facility."):
                        facilityID = key.partition(".")[-1]
                        toChange = (
                            db.session.query(Facility)
                            .filter(facilityID == Facility.id)
                            .first()
                        )
                        db.session.delete(toChange)
                    elif key.startswith("delete_activity."):
                        partition = key.split(".")
                        facilityID = partition[1]
                        activityID = (
                            db.session.query(Activity)
                            .filter(partition[2] == Activity.name)
                            .first()
                            .id
                        )
                        toChange = (
                            db.session.query(ActivityLocation)
                            .filter(
                                activityID == ActivityLocation.activityId,
                                facilityID == ActivityLocation.facilityId,
                            )
                            .first()
                        )
                        db.session.delete(toChange)
                    elif key.startswith("addActivity."):
                        partition = key.split(".")
                        facilityID = partition[1]
                        session["addActToFac"] = facilityID
                        logging.warning(session["addActToFac"])
                        return redirect("/manage_add_activity")
                    elif key.startswith("edit_activity."):
                        partition = key.split(".")
                        session["editActivityName"] = partition[2]
                        session["editFacilityID"] = partition[1]
                        logging.warning(
                            f'Editing activity "{partition[2]}" of requested'
                        )
                        return redirect("/manage_add_activity")
                    elif key == "addFacility":
                        return redirect("/manage_add_facility")
            db.session.commit()

        f = db.session.query(Facility).all()
        facilities = []
        for facility in f:
            activityLocations = (
                db.session.query(ActivityLocation)
                .filter(ActivityLocation.facilityId == facility.id)
                .group_by(ActivityLocation.activityId)
                .all()
            )
            activities = []
            for al in activityLocations:
                a = db.session.query(Activity).get(al.activityId)
                activities.append(a.name)

            facilities.append(
                {
                    "id": facility.id,
                    "name": facility.name,
                    "capacity": facility.capacity,
                    "opens": numericToTime(facility.opens),
                    "closes": numericToTime(facility.closes),
                    "activities": activities,
                }
            )
        return render_template(
            "manage_activities_facilities.html", facilities=facilities
        )
    return redirect("/")


@app.route("/manage_add_facility", methods=["GET", "POST"])
def ManageAddFacility():
    if AccountTypeCheck() == "Manager":
        alert = {"msg": "", "color": "danger"}
        if request.method == "POST":
            logging.warning(session["addActToFac"])
            if "facilityName" in request.form:
                # only allow alpha characters and spaces
                if request.form["facilityName"].replace(" ", "").isalpha():
                    if request.form["facilityOpen"] == "":
                        alert["msg"] = "Invalid open time."
                    elif request.form["facilityClose"] == "":
                        alert["msg"] = "Invalid close time."
                    else:
                        openTime = timeToNumeric(request.form["facilityOpen"])
                        closeTime = timeToNumeric(request.form["facilityClose"])

                        newFac = Facility(
                            name=request.form["facilityName"],
                            capacity=request.form["facilityCapacity"],
                            opens=openTime,
                            closes=closeTime,
                        )
                        db.session.add(newFac)
                        db.session.commit()
                        alert["msg"] = "Activity Added."
                        alert["color"] = "success"
                        alert["start"] = "Success"
                        return render_template(
                            "manage_add_facility.html",
                            alert=alert,
                            redirect={
                                "url": "/manage_activities_facilities",
                                "timeout": "2000",
                            },
                        )
                else:
                    alert["msg"] = "Invalid name."
        if alert["msg"]:
            return render_template("manage_add_facility.html", alert=alert)
        else:
            return render_template("manage_add_facility.html")
    return redirect("/")


@app.route("/manage_add_activity", methods=["GET", "POST"])
def ManageAddActivity():
    if AccountTypeCheck() == "Manager":
        alert = {"msg": "", "color": "danger"}
        args = {}
        if "addActToFac" in session:
            facility = db.session.query(Facility).get(session["addActToFac"])
            facName = facility.name
            facCapacity = facility.capacity
        if "editActivityName" in session:
            activity = (
                db.session.query(Activity)
                .filter(Activity.name == session["editActivityName"])
                .first()
            )
            facility = db.session.query(Facility).get(session["editFacilityID"])
            facName = facility.name
            facCapacity = facility.capacity
            activityLocations = (
                db.session.query(ActivityLocation)
                .filter(
                    and_(
                        ActivityLocation.activityId == activity.id,
                        ActivityLocation.facilityId == facility.id,
                    )
                )
                .all()
            )
            args = {
                "isEditing": True,
                "activityName": activity.name,
                "activityCapacity": activity.capacity,
                "activityLocations": [],
            }
            if activity.length:
                args["activityLength"] = activity.length

            if activity.capacity is None:
                args["activityCapacity"] = 0

            for al in activityLocations:
                if al.startDay:
                    args["activityLocations"].append(
                        {
                            "id": al.id,
                            "startDay": al.startDay,
                            "startTime": numericToTime(al.startTime),
                        }
                    )

        if request.method == "POST":
            if "activityName" in request.form:
                # checkbox values are only sent if they're true, so we check they exist
                specificDay = "activitySpecificDay" in request.form
                lengthDefined = "activityLengthDefined" in request.form
                startDays = []
                startTimes = []
                # When editing an activity, activityLocation IDs are given along with each startDay/Time. They are stored here for later use.
                editedIDs = []
                # ActivityLocation IDs requested for deletion
                deleteIDs = []
                if specificDay and lengthDefined:
                    for key in request.form:
                        if "activityTime" in key:
                            startTimes.append(request.form[key])
                            if "isEditing" in args and args["isEditing"]:
                                editedIDs.append(key.replace("activityTime", ""))
                        elif "activityStartDay" in key:
                            startDays.append(request.form[key])
                        elif "deleteActivityLocation" in key:
                            deleteIDs.append(request.form[key])
                # only allow alpha characters and spaces
                if request.form["activityName"].replace(" ", "").isalpha():
                    if specificDay and len(startDays) == 0:
                        alert["msg"] = "Invalid start day."
                    elif specificDay and len(startTimes) == 0:
                        alert["msg"] = "Invalid start time."
                    elif (lengthDefined or specificDay) and request.form[
                        "activityLength"
                    ] == "":
                        if specificDay:
                            alert[
                                "msg"
                            ] = "Length must be set for scheduled activities."
                        else:
                            alert["msg"] = "Invalid length."
                    else:
                        if "isEditing" in args and args["isEditing"]:
                            setattr(activity, "name", str(request.form["activityName"]))
                            if not request.form["activityCapacity"]:
                                setattr(activity, "capacity", None)
                            else:
                                setattr(
                                    activity,
                                    "capacity",
                                    int(request.form["activityCapacity"]),
                                )
                            if lengthDefined:
                                setattr(
                                    activity,
                                    "length",
                                    int(request.form["activityLength"]),
                                )
                        else:
                            newAcc = Activity(name=request.form["activityName"])
                            if not request.form["activityCapacity"]:
                                newAcc.capacity = None
                            else:
                                newAcc.capacity = request.form["activityCapacity"]
                            if lengthDefined:
                                newAcc.length = request.form["activityLength"]

                            db.session.add(newAcc)
                        db.session.commit()

                        if not specificDay:
                            if not "isEditing" in args and args["isEditing"]:
                                newAccLoc = ActivityLocation(
                                    activityId=newAcc.id,
                                    facilityId=session["addActToFac"],
                                )
                                db.session.add(newAccLoc)
                                db.session.commit()
                        else:
                            for i in range(len(startDays)):
                                if "isEditing" in args and args["isEditing"]:
                                    acl = db.session.query(ActivityLocation).get(
                                        editedIDs[i]
                                    )
                                    if not acl:
                                        acl = ActivityLocation(
                                            activityId=activity.id,
                                            facilityId=facility.id,
                                            startDay=startDays[i],
                                            startTime=timeToNumeric(startTimes[i]),
                                        )
                                        db.session.add(acl)
                                    else:
                                        acl.startDay = startDays[i]
                                        acl.startTime = timeToNumeric(startTimes[i])
                                else:
                                    newAccLoc = ActivityLocation(
                                        activityId=newAcc.id,
                                        facilityId=session["addActToFac"],
                                        startDay=startDays[i],
                                        startTime=timeToNumeric(startTimes[i]),
                                    )
                                    db.session.add(newAccLoc)
                            db.session.commit()

                        if "isEditing" in args and args["isEditing"]:
                            for id in deleteIDs:
                                db.session.delete(
                                    db.session.query(ActivityLocation).get(id)
                                )

                            db.session.commit()
                            session.pop("editActivityName")
                            session.pop("editFacilityID")
                        else:
                            session.pop("addActToFac")
                        alert["msg"] = "Added Activity."
                        alert["start"] = "Success"
                        alert["color"] = "success"
                        return render_template(
                            "manage_add_activity.html",
                            alert=alert,
                            redirect={
                                "url": "/manage_activities_facilities",
                                "timeout": "2000",
                            },
                            **args,
                        )
                else:
                    alert["msg"] = "Invalid name"
        if alert["msg"]:
            return render_template(
                "manage_add_activity.html",
                alert=alert,
                facName=facName,
                facCapacity=facCapacity,
                **args,
            )
        else:
            return render_template(
                "manage_add_activity.html",
                facName=facName,
                facCapacity=facCapacity,
                **args,
            )
    return redirect("/")


@app.route("/manage_staff", methods=["GET", "POST"])
def ManageStaff():
    if AccountTypeCheck() == "Manager":
        if request.method == "POST":
            if "function" in request.form:
                user = Account.query.filter(
                    Account.id == request.form["userID"]
                ).first()
                newType = request.form["option"]
                if newType == "User":
                    user.accountType = AccountType.User
                elif newType == "Employee":
                    user.accountType = AccountType.Employee
                elif newType == "Manager":
                    user.accountType = AccountType.Manager
                db.session.commit()
            elif "add_account" in request.form:
                session["manageAccType"] = request.form["add_account"]
                return redirect("/manage_add_account")
            else:
                for key in request.form:
                    if key.startswith("delete_account."):
                        userID = key.partition(".")[-1]
                        toChange = (
                            db.session.query(Booking)
                            .filter(userID == Booking.accountId)
                            .all()
                        )
                        for a in toChange:
                            db.session.delete(a)
                        toChange = (
                            db.session.query(Receipt)
                            .filter(userID == Receipt.accountId)
                            .all()
                        )
                        for a in toChange:
                            db.session.delete(a)
                        toChange = (
                            db.session.query(Address)
                            .filter(userID == Address.accountId)
                            .all()
                        )
                        for a in toChange:
                            db.session.delete(a)
                        toChange = (
                            db.session.query(Membership)
                            .filter(userID == Membership.accountId)
                            .all()
                        )
                        for a in toChange:
                            db.session.delete(a)
                        toChange = (
                            db.session.query(Account).filter(userID == Account.id).all()
                        )
                        for a in toChange:
                            db.session.delete(a)
                        db.session.commit()
        users = Account.query.all()
        return render_template(
            "manage_staff.html", users=users, AccountType=AccountType
        )
    return redirect("/")


@app.route("/manage_add_account", methods=["GET", "POST"])
def ManageAddAccount():
    if AccountTypeCheck() == "Manager":
        form = CreateAccountForm()

        if request.method == "GET":
            return render_template(
                "manage_add_account.html", form=form, accType=session["manageAccType"]
            )

        if not form.validate_on_submit():
            logging.warning("Signup: Invalid form submitted")
            return render_template(
                "manage_add_account.html",
                form=form,
                alert={"color": "danger", "msg": "Invalid form."},
                accType=session["manageAccType"],
            )

        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        post_code = form.post_code.data
        date_of_birth = form.date_of_birth.data

        address_line_1 = form.AddressLine1.data
        address_line_2 = form.AddressLine2.data
        address_line_3 = form.AddressLine3.data
        city = form.City.data
        country = form.Country.data
        phone_number = form.Phone_Number.data

        user = db.session.query(Account).filter(Account.username == username).first()
        if user:
            return render_template(
                "manage_add_account.html",
                form=form,
                alert={
                    "msg": "Username/Password taken, please try another",
                    "color": "danger",
                },
                accType=session["manageAccType"],
            )
        user = db.session.query(Account).filter(Account.email == email).first()
        if user:
            return render_template(
                "manage_add_account.html",
                form=form,
                alert={
                    "msg": "Email address taken, please try another",
                    "color": "danger",
                },
                accType=session["manageAccType"],
            )

        new_user = Account(
            username=username,
            email=email,
            firstname=first_name,
            surname=last_name,
            dob=date_of_birth,
        )
        new_user.set_password(password)

        if session["manageAccType"] == "addManager":
            new_user.accountType = AccountType.Manager
        elif session["manageAccType"] == "addEmployee":
            new_user.accountType = AccountType.Employee
        elif session["manageAccType"] == "addUser":
            new_user.accountType = AccountType.User

        # Commit user so we can get its ID to put in the address.
        with app.app_context():
            db.session.add(new_user)
            db.session.flush()

            address = Address(
                accountId=new_user.id,
                line1=address_line_1,
                line2=address_line_2,
                line3=address_line_3,
                city=city,
                country=country,
                postcode=post_code,
                phone=phone_number,
            )
            db.session.add(address)

            db.session.commit()

        session.pop("manageAccType")
        # Render page with success message, then redirect to login after 2s (2000ms).
        return render_template(
            "manage_add_account.html",
            form=form,
            alert={"start": "Success", "msg": "Account created.", "color": "success"},
            redirect={"url": "/manage_staff", "timeout": "2000"},
        )
    return redirect("/")


@app.route("/manage_discount", methods=["GET", "POST"])
def ManageDiscount():
    if AccountTypeCheck() == "Manager":
        discountValue = (
            db.session.query(MembershipPrices)
            .filter(MembershipPrices.name == "Discount")
            .first()
        )
        if request.method == "POST":
            if len(request.form["discount_value"]) > 0:
                val = float(request.form["discount_value"]) / 100
                discountValue.price = val
        db.session.commit()
        return render_template("manage_discount.html", discountValue=discountValue)
    return redirect("/")


@app.route("/management_graphs", methods=["GET", "POST"])
def ManageGraphs():
    if AccountTypeCheck() == "Manager":
        facilities = db.session.query(Facility).filter().all()
        activities = db.session.query(Activity).filter().all()
        activityLocations = db.session.query(ActivityLocation).filter().all()
        bookings = db.session.query(Booking).filter().all()

        max = len(facilities)
        for f in facilities:
            num = 0
            for a in activityLocations:
                if a.facilityId == f.id:
                    num += 1
                if max < num:
                    max = num

        w, h = max, len(facilities) + 1
        Matrix = [[[0 for x in range(2)] for z in range(w)] for y in range(h)]

        for i, f in enumerate(facilities):
            Matrix[0][i][0] = f.name
            Matrix[0][i][1] = 0

        for i in range(h):
            for contents in range(w):
                if i != 0:
                    Matrix[i][contents][0] = ""
                    Matrix[i][contents][1] = 0

        for booking in bookings:
            for activityLocation in activityLocations:
                if booking.activityLocation == activityLocation.id:
                    facility = (
                        db.session.query(Facility)
                        .filter(activityLocation.facilityId == Facility.id)
                        .first()
                    )
                    activity = (
                        db.session.query(Activity)
                        .filter(activityLocation.activityId == Activity.id)
                        .first()
                    )

                    index = -1
                    for i in range(len(facilities)):
                        if Matrix[0][i][0] == facility.name:
                            index = i
                            Matrix[0][i][1] += 1
                            break

                    found = False
                    for i in range(max):
                        if Matrix[index + 1][i][0] == activity.name:
                            found = True
                            Matrix[index + 1][i][1] += 1
                            break
                    if found == False:
                        for i in range(max):
                            if Matrix[index + 1][i][0] == "":
                                Matrix[index + 1][i][0] = activity.name
                                Matrix[index + 1][i][1] += 1
                                break

        Usage = [["Single", 0, 0, 0], ["Monthly", 0, 0, 0], ["Yearly", 0, 0, 0]]

        membershipPrices = db.session.query(MembershipPrices).filter().all()
        memberships = db.session.query(Membership).filter().all()

        single = 0
        actSingle = 0

        monthly = 0
        actMonthly = 0

        yearly = 0
        actYearly = 0

        for mem in memberships:
            if mem.entryType == 0:
                single += 1
                if mem.active == True:
                    actSingle += 1
            elif mem.entryType == 1:
                monthly += 1
                if mem.active == True:
                    actMonthly += 1
            elif mem.entryType == 2:
                yearly += 1
                if mem.active == True:
                    actYearly += 1

        if single != 0:
            Usage[0][1] = (
                single
                * db.session.query(MembershipPrices)
                .filter(MembershipPrices.name == "Single")
                .first()
                .price
            )
            Usage[0][2] = single
            Usage[0][3] = actSingle

        if monthly != 0:
            Usage[1][1] = (
                monthly
                * db.session.query(MembershipPrices)
                .filter(MembershipPrices.name == "Month")
                .first()
                .price
            )
            Usage[1][2] = monthly
            Usage[1][3] = actMonthly

        if yearly != 0:
            Usage[2][1] = (
                yearly
                * db.session.query(MembershipPrices)
                .filter(MembershipPrices.name == "Year")
                .first()
                .price
            )
            Usage[2][2] = yearly
            Usage[2][3] = actYearly

        data = {"Matrix": Matrix, "Width": w, "Height": h, "Usage": Usage}
        return render_template("management_graphs.html", data=data)
    return redirect("/")


# @app.route("/card_payment", methods=["GET", "POST"])
# def Card_Payment():
#     item = request.url[-1]  # membership the user wants.
#
#     # print(item)
#     form = CardPayments()
#     if form.validate_on_submit():
#         t = (
#             Address.query.filter_by(accountId=current_user.id).first().id
#         )  # get's the address id.
#
#         # print(t)
#
#         p = CardDetails(
#             name=form.Name.data,
#             accountId=current_user.id,
#             addressId=t,
#             cardNumber=form.Card_Number.data,
#             expiryMonth=form.Expiry_Date.data.month,
#             expiryYear=form.Expiry_Date.data.year,
#             cvv=form.CVV.data,
#         )
#
#         db.session.add(p)
#         db.session.commit()
#
#         return redirect(url_for("Card_Payment"))
#
#     return render_template(
#         "card_payments.html", form=form, membership=item, prices=EntryType
#     )


@app.route("/checkout", methods=["GET", "POST"])
def BookingCheckout():
    print(session["basket"])
    if not "basket" in session or len(session["basket"]) == 0:
        return redirect("/pricing")

    singlePrice = (
        db.session.query(MembershipPrices)
        .filter(MembershipPrices.name == "Single")
        .first()
        .price
    )
    discount = (
        db.session.query(MembershipPrices)
        .filter(MembershipPrices.name == "Discount")
        .first()
        .price
    )
    discountString = ""
    if discount:
        discountString = str(int(discount * Decimal(100))) + "%"
    priceBeforeDiscount = Decimal(0.0)
    basket = session["basket"]
    bookings = []
    for bk in basket:
        if bk["accountId"] != current_user.id:
            continue
        booking = {"id": bk["id"], "teamBooking": bk["teamBooking"]}
        al = db.session.query(ActivityLocation).get(bk["activityLocation"])
        act = db.session.query(Activity).get(al.activityId)
        fac = db.session.query(Facility).get(al.facilityId)
        booking["name"] = act.name
        booking["facility"] = fac.name
        booking["time"] = bk["start"] + " — " + bk["end"]
        booking["price"] = singlePrice

        priceBeforeDiscount += singlePrice

        bookings.append(booking)

    totalPrice = priceBeforeDiscount
    discountSubtracted = Decimal(0.0)
    hasDiscount = False
    if len(basket) >= 3:
        withinSevenDays = True
        first = datetime.datetime.strptime(basket[0]["start"], "%a %d/%m/%y %H:%M")
        for bk in basket:
            if (
                datetime.datetime.strptime(bk["start"], "%a %d/%m/%y %H:%M") - first
            ).days > 7:
                withinSevenDays = False
                break

        if withinSevenDays:
            hasDiscount = True
            discountSubtracted = totalPrice * discount
            totalPrice -= discountSubtracted

    return render_template(
        "checkout.html",
        bookings=bookings,
        priceBeforeDiscount=priceBeforeDiscount.quantize(
            Decimal(".01"), rounding=ROUND_UP
        ),
        totalPrice=totalPrice.quantize(Decimal(".01"), rounding=ROUND_UP),
        discount=hasDiscount,
        discountString=discountString,
        discountSubtracted=discountSubtracted.quantize(
            Decimal(".01"), rounding=ROUND_DOWN
        ),
    )


# deleteBasketItem removes an item from a user's basket.
# Always returns 201, since the end result is always that the basket item doesn't exist.
@app.route("/checkout/<basketItemId>", methods=["DELETE"])
@login_required
def deleteBasketItem(basketItemId):
    if "basket" not in session:
        return "", 201
    newBasket = []
    for item in session["basket"]:
        if (
            str(item["id"]) == str(basketItemId)
            and item["accountId"] == current_user.id
        ):
            continue
        newBasket.append(item)

    session["basket"] = newBasket
    return "", 201


def findOrCreateStripeUser(current_user):
    customerSearch = stripe.Customer.search(
        query=f'metadata["accountId"]:"{current_user.id}"', limit=1
    )

    if len(customerSearch.data) == 1:
        logging.debug("Found existing Stripe user")
        return customerSearch.data[0]

    address = (
        db.session.query(Address).filter(Address.accountId == current_user.id).first()
    )
    customerAddr = {}
    if address is not None:
        customerAddr = {
            "city": address.city,
            "line1": address.line1,
            "line2": address.line2,
            "postal_code": address.postcode,
        }

    logging.debug("Couldn't existing Stripe user, creating new...")

    customerDetails = {
        "address": customerAddr,
        "metadata": {"accountId": current_user.id},
        "email": current_user.email,
        "name": current_user.firstname + " " + current_user.surname,
    }

    if address is not None:
        customerDetails["phone"] = address.phone

    customer = stripe.Customer.create(**customerDetails)

    return customer


@app.route("/pay/gold", methods=["GET"])
@login_required
def payGold():
    # First, create/get a stripe user so we can bind the subscription to the user's account.
    try:
        customer = findOrCreateStripeUser(current_user)
        checkout_session = stripe.checkout.Session.create(
            line_items=[{"price": "price_1MnWN0CvuWQSx8eZDCv22dnH", "quantity": 1}],
            customer=customer.id,
            mode="subscription",
            success_url=url_for("success", _external=True, purchase_type="gold")
            + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("cancel", _external=True),
        )
    except Exception as e:
        return str(e)

    if "subscriptionCheckoutIds" not in localSession:
        localSession["subscriptionCheckoutIds"] = {}

    subscriptionCheckoutIds = localSession["subscriptionCheckoutIds"]
    subscriptionCheckoutIds[checkout_session.id] = (current_user.id, "gold")
    localSession["subscriptionCheckoutIds"] = subscriptionCheckoutIds
    return redirect(checkout_session.url)


@app.route("/pay/platinum", methods=["GET"])
@login_required
def payPlatinum():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[{"price": "price_1MoBEjCvuWQSx8eZBMNPIZqF", "quantity": 1}],
            mode="subscription",
            success_url=url_for("success", _external=True, purchase_type="platinum")
            + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("cancel", _external=True),
        )
    except Exception as e:
        return str(e)

    if "subscriptionCheckoutIds" not in localSession:
        localSession["subscriptionCheckoutIds"] = {}

    subscriptionCheckoutIds = localSession["subscriptionCheckoutIds"]
    subscriptionCheckoutIds[checkout_session.id] = (current_user.id, "platinum")
    localSession["subscriptionCheckoutIds"] = subscriptionCheckoutIds
    return redirect(checkout_session.url)


@app.route("/pay/single", methods=["GET"])
@login_required
def paySingleSession():
    if "basket" not in session or len(session["basket"]) == 0:
        return "Basket Empty.", 400

    basket = list(
        filter(lambda bk: bk["accountId"] == current_user.id, session["basket"])
    )
    args = {}
    if len(basket) >= 3:
        withinSevenDays = True
        first = datetime.datetime.strptime(basket[0]["start"], "%a %d/%m/%y %H:%M")
        for bk in basket:
            if (
                datetime.datetime.strptime(bk["start"], "%a %d/%m/%y %H:%M") - first
            ).days > 7:
                withinSevenDays = False
                break

        if withinSevenDays:
            discount_pct = int(
                db.session.query(MembershipPrices)
                .filter(MembershipPrices.name == "Discount")
                .first()
                .price
                * 100
            )
            coupon = stripe.Coupon.create(percent_off=discount_pct, duration="once")
            args = {"discounts": [{"coupon": coupon.id}]}
    try:
        customer = findOrCreateStripeUser(current_user)
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {"price": "price_1MnlF4CvuWQSx8eZOVvPJ5Hi", "quantity": len(basket)}
            ],
            mode="payment",
            customer=customer.id,
            success_url=url_for("success", _external=True, purchase_type="single")
            + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("BookingCheckout", _external=True),
            **args,
        )
    except Exception as e:
        return str(e)

    if "checkoutIds" not in localSession:
        localSession["checkoutIds"] = {}

    checkoutIds = localSession["checkoutIds"]
    checkoutIds[checkout_session.id] = current_user.id
    localSession["checkoutIds"] = checkoutIds
    return redirect(checkout_session.url)


@app.route("/success/<purchase_type>", methods=["GET", "POST"])
@login_required
def success(purchase_type=None):
    session_id = request.args.get("session_id")

    if purchase_type == "single":
        # Check to ensure stripe payment session is real before doing anything
        if (
            "checkoutIds" not in localSession
            or session_id not in localSession["checkoutIds"]
            or localSession["checkoutIds"][session_id] != current_user.id
        ):
            return "Basket not found.", 400
        checkoutIds = localSession["checkoutIds"]
        checkoutIds.pop(session_id)
        localSession["checkoutIds"] = checkoutIds

        checkoutSession = stripe.checkout.Session.retrieve(session_id)

        purchased = list(
            filter(lambda bk: bk["accountId"] == current_user.id, session["basket"])
        )
        discount = (
            db.session.query(MembershipPrices)
            .filter(MembershipPrices.name == "Discount")
            .first()
            .price
        )
        price = (
            db.session.query(MembershipPrices)
            .filter(MembershipPrices.name == "Single")
            .first()
            .price
        )
        r = Receipt(
            accountId=current_user.id,
            date=datetime.date.today(),
            itemCount=len(purchased),
            itemPrice=price,
            stripePaymentIntentId=checkoutSession.payment_intent,
        )
        if len(purchased) >= 3:
            withinSevenDays = True
            first = datetime.datetime.strptime(
                purchased[0]["start"], "%a %d/%m/%y %H:%M"
            )
            for bk in purchased:
                if (
                    datetime.datetime.strptime(bk["start"], "%a %d/%m/%y %H:%M") - first
                ).days > 7:
                    withinSevenDays = False
                    break

            if withinSevenDays:
                r.discountPct = int(float(discount) * 100)

        name = "Single Session:\n"
        for i, bk in enumerate(purchased):
            if i == len(purchased) - 1 and len(purchased) != 1:
                name += "\nand "
            elif i != 0:
                name += ",\n"
            acl = db.session.query(ActivityLocation).get(bk["activityLocation"])
            act = db.session.query(Activity).get(acl.activityId)
            fac = db.session.query(Facility).get(acl.facilityId)
            name += f"{act.name} ({fac.name})"

        r.itemName = name

        db.session.add(r)
        db.session.flush()

        if "basket" not in session or len(session["basket"]) == 0:
            return "Basket Empty.", 400
        newBasket = []
        for bk in session["basket"]:
            if bk["accountId"] == current_user.id:
                start = datetime.datetime.strptime(bk["start"], "%a %d/%m/%y %H:%M")
                endTime = datetime.datetime.strptime(bk["end"], "%H:%M")
                end = start.replace(hour=endTime.hour, minute=endTime.minute)
                t = Booking(
                    accountId=current_user.id,
                    activityLocation=bk["activityLocation"],
                    start=start,
                    end=end,
                    teamBooking=bk["teamBooking"],
                    receiptId=r.id,
                )
                # FIXME: Check booking not already taken
                db.session.add(t)
                continue
            newBasket.append(bk)
        db.session.commit()
        session["basket"] = newBasket

        db.session.add(r)
        db.session.commit()
    elif purchase_type == "gold":
        if (
            "subscriptionCheckoutIds" not in localSession
            or session_id not in localSession["subscriptionCheckoutIds"]
            or localSession["subscriptionCheckoutIds"][session_id][0] != current_user.id
        ):
            return "Basket not found.", 400
        subscriptionCheckoutIds = localSession["subscriptionCheckoutIds"]
        if subscriptionCheckoutIds[session_id][1] != "gold":
            return "Basket not found.", 400

        subscriptionCheckoutIds.pop(session_id)
        gold = (
            db.session.query(MembershipPrices)
            .filter(MembershipPrices.name == "Month")
            .first()
        )
        start = datetime.datetime.now()
        end = start.replace(month=start.month + 1)
        # FIXME: Ensure membership validity gets updated each month by checking w/ stripe
        r = Receipt(
            accountId=current_user.id,
            date=start,
            itemCount=1,
            itemPrice=gold.price,
            itemName="Gold Subscription (1 Month)",
        )

        m = Membership(
            accountId=current_user.id,
            entryType=gold.id,
            startDate=start,
            endDate=end,
        )

        db.session.add(r)
        db.session.add(m)
        db.session.commit()

    elif purchase_type == "platinum":
        if (
            "subscriptionCheckoutIds" not in localSession
            or session_id not in localSession["subscriptionCheckoutIds"]
            or localSession["subscriptionCheckoutIds"][session_id][0] != current_user.id
        ):
            return "Basket not found.", 400
        subscriptionCheckoutIds = localSession["subscriptionCheckoutIds"]
        if subscriptionCheckoutIds[session_id][1] != "platinum":
            return "Basket not found.", 400

        subscriptionCheckoutIds.pop(session_id)
        platinum = (
            db.session.query(MembershipPrices)
            .filter(MembershipPrices.name == "Year")
            .first()
        )
        start = datetime.datetime.now()
        end = start.replace(year=start.year + 1)
        r = Receipt(
            accountId=current_user.id,
            date=start,
            itemCount=1,
            itemPrice=platinum.price,
            itemName="Platinum Subscription (1 Year)",
        )

        m = Membership(
            accountId=current_user.id,
            entryType=platinum.id,
            startDate=start,
            endDate=end,
        )

        db.session.add(r)
        db.session.add(m)
        db.session.commit()

    return redirect(url_for("bookings"))


@app.route("/cancel", methods=["GET", "POST"])
def cancel():
    return render_template("cancel.html")


@app.route("/pricing", methods=["GET", "POST"])
def pricing():
    allPrices = db.session.query(MembershipPrices).all()
    if current_user.is_authenticated:
        membership = (
            db.session.query(Membership)
            .filter(Membership.accountId == current_user.id)
            .first()
        )
        if membership:
            return render_template(
                "pricing.html",
                membership=membership,
                prices=allPrices,
                currentTime=datetime.datetime.now(),
            )
            # if membership exists then show membership
        elif not membership:
            return render_template("pricing.html", prices=allPrices)
            # if membership does not exist then show available memberships.
    else:
        return render_template("pricing.html", prices=allPrices)


@app.route("/facilities", methods=["GET", "POST"])
# facilities returns a list view of the centre's facilities,
# with information such as capacity, opening/closing times, and available activities.
def facilities():
    f = db.session.query(Facility).all()
    facilities = []
    for facility in f:
        activityLocations = (
            db.session.query(ActivityLocation)
            .filter(ActivityLocation.facilityId == facility.id)
            .all()
        )
        activities = []
        for al in activityLocations:
            a = db.session.query(Activity).get(al.activityId)
            activities.append(a.name)

        facilities.append(
            {
                "id": facility.id,
                "name": facility.name,
                "capacity": facility.capacity,
                "opens": numericToTime(facility.opens),
                "closes": numericToTime(facility.closes),
                "activities": activities,
            }
        )

    return render_template("facilities.html", facilities=facilities)


# Check if a class is bookable on the given day. Since classes have fixed times, time overlap checking isn't needed.
def classBookable(activityLocationId, day, accountId=None):
    acl = db.session.query(ActivityLocation).get(activityLocationId)
    bookings = (
        db.session.query(Booking)
        .filter(Booking.activityLocation == activityLocationId)
        .all()
    )
    availableCapacity = db.session.query(Facility).get(acl.facilityId).capacity
    delta = datetime.timedelta(days=1)

    # dont show stuff that's already happened as bookable
    if day.weekday() > acl.startDay - 1:
        # delta = datetime.timedelta(days=-1)
        return False

    # "day" arg is the searched date, even though the class might not be on that date.
    # increment the searched date to match the class' weekday.
    while acl.startDay - 1 != day.weekday():
        day += delta

    for booking in bookings:
        if booking.start.date() != day.date():
            continue
        if booking.teamBooking is True:
            return False

        # Don't show classes you've already booked
        if accountId is not None and booking.accountId == accountId:
            print(f"AL{activityLocationId} not bookable as user has already booked it")
            return False
        availableCapacity -= 1

    if availableCapacity <= 0:
        print(f"AL{activityLocationId} not bookable as no slots available")
    return availableCapacity > 0


# Check if an activity is bookable on the given period.
# Bookings are allowed in 30 minute intervals so that available capacity can be checked
# over a regular interval.
def activityBookable(activityLocationId, start, end, accountId=None):
    start = start.replace(second=0, microsecond=0)
    end = end.replace(second=0, microsecond=0)
    acl = db.session.query(ActivityLocation).get(activityLocationId)
    act = db.session.query(Activity).get(acl.activityId)
    availableCapacity = db.session.query(Facility).get(acl.facilityId).capacity
    sameFacilityACLs = (
        db.session.query(ActivityLocation)
        .filter(ActivityLocation.facilityId == acl.facilityId)
        .all()
    )
    # Assemble filter for all bookings with activityLocations with the same facility as our main one
    bookingFilters = []
    for facl in sameFacilityACLs:
        bookingFilters.append(Booking.activityLocation == facl.id)

    bookings = db.session.query(Booking).filter(or_(*bookingFilters)).all()
    startTime = start
    periodIndex = 0
    periodCapacities = [int(availableCapacity)]
    # Loop over 30 minute intervals, calculating the available capacity for each.
    while startTime != end:
        for booking in bookings:
            if booking.start.date() != start.date():
                continue
            if booking.start <= startTime and booking.end > startTime:
                periodCapacities[periodIndex] -= 1
                if accountId is not None and booking.accountId == accountId:
                    return False

        if periodCapacities[periodIndex] == 0:
            return False

        periodCapacities.append(int(availableCapacity))
        periodIndex += 1
        startTime += datetime.timedelta(minutes=30)
    return True


# Returns the 30-minute slots available for an activityLocation on a given day.
def availableSlots(activityLocationId, day):
    day = day.replace(second=0, microsecond=0)
    acl = db.session.query(ActivityLocation).get(activityLocationId)
    act = db.session.query(Activity).get(acl.activityId)
    fac = db.session.query(Facility).get(acl.facilityId)
    openHour, openMinute = numericToTuple(fac.opens)
    opening = day.replace(hour=openHour, minute=openMinute)
    closeHour, closeMinute = numericToTuple(fac.closes)
    closing = day.replace(hour=closeHour, minute=closeMinute)

    availableCapacity = db.session.query(Facility).get(acl.facilityId).capacity
    sameFacilityACLs = (
        db.session.query(ActivityLocation)
        .filter(ActivityLocation.facilityId == acl.facilityId)
        .all()
    )
    # Assemble filter for all bookings with activityLocations with the same facility as our main one
    bookingFilters = []
    for facl in sameFacilityACLs:
        bookingFilters.append(Booking.activityLocation == facl.id)

    bookings = db.session.query(Booking).filter(or_(*bookingFilters)).all()
    periods = []
    # Loop over 30 minute intervals, calculating the available capacity for each.
    while opening != closing:
        if opening < datetime.datetime.now():
            opening += datetime.timedelta(minutes=30)
            continue
        p = [
            opening.strftime("%H:%M"),
            (opening + datetime.timedelta(minutes=30)).strftime("%H:%M"),
        ]
        available = availableCapacity
        for booking in bookings:
            if booking.start.date() != opening.date():
                continue
            if booking.start <= opening and booking.end > opening:
                available -= 1

        if available > 0:
            periods.append(p)
        opening += datetime.timedelta(minutes=30)
    return periods


# getActivityData returns data necessary to render the booking pages.
def getActivityData(auth=False, accountId=None, searchedDatetime=None):
    currentDatetime = datetime.datetime.now()
    currentDate = currentDatetime.strftime("%Y-%m-%d")
    if not auth:
        searchedDatetime = None

    if (not auth) or searchedDatetime is None:
        searchedDatetime = currentDatetime
        searchedDate = currentDate
    else:
        searchedDate = searchedDatetime.strftime("%Y-%m-%d")

    a = db.session.query(Activity).all()
    activities = []
    classes = []

    # Get dates for every day in the week
    weekDayDates = [
        (
            searchedDatetime
            - datetime.timedelta(days=(searchedDatetime.weekday() % 7) - i)
        )
        for i in range(7)
    ]
    weekDayDateStrings = [dateSuffix(date.day) for date in weekDayDates]
    weekDayDatesPast = [(currentDatetime > date) for date in weekDayDates]
    # Don't show dates if not logged in.
    if accountId is None:
        weekDayDateStrings = ["" for _ in weekDayDates]
        weekDayDatesPast = [False for _ in weekDayDates]

    personalBasket = {}
    if "basket" in session:
        pb = list(
            filter(lambda bk: bk["accountId"] == current_user.id, session["basket"])
        )
        for basketItem in pb:
            personalBasket[basketItem["id"]] = True

    for act in a:
        activity = {
            "id": act.id,
            "name": act.name,
            "facilities": {},
        }
        if act.length is not None and act.length > 0:
            activity["length"] = act.length

        isClass = False
        als = (
            db.session.query(ActivityLocation)
            .filter(ActivityLocation.activityId == act.id)
            .order_by(ActivityLocation.startTime)
        )
        for al in als:
            if al.facilityId not in activity["facilities"]:
                facility = db.session.query(Facility).get(al.facilityId)
                if facility is not None:
                    activity["facilities"][al.facilityId] = facility.name
            if al.startDay and al.startTime:
                if "times" not in activity:
                    activity["times"] = {}

                bookable = True

                acl = db.session.query(ActivityLocation).get(al.id)
                if db.session.query(Facility).get(acl.facilityId) is not None:
                    if current_user.is_authenticated:
                        bookable = classBookable(
                            al.id, searchedDatetime, accountId=accountId
                        )

                dayName = numberToDay(al.startDay)
                if dayName not in activity["times"]:
                    activity["times"][dayName] = []

                classObject = {
                    "facilityId": al.facilityId,
                    "activityLocationId": al.id,
                    "start": numericToTime(al.startTime),
                    "end": numericToTime(al.startTime + act.length),
                    "bookable": bookable,
                }

                if accountId is not None and classObject["bookable"]:
                    classStart = datetime.datetime.strptime(
                        classObject["start"], "%H:%M"
                    )
                    classStart = weekDayDates[al.startDay - 1].replace(
                        hour=classStart.hour,
                        minute=classStart.minute,
                        second=0,
                        microsecond=0,
                    )
                    classEnd = datetime.datetime.strptime(classObject["end"], "%H:%M")
                    classEnd = weekDayDates[al.startDay - 1].replace(
                        hour=classEnd.hour,
                        minute=classEnd.minute,
                        second=0,
                        microsecond=0,
                    )
                    classHash = hash(
                        frozenset(
                            {
                                "accountId": accountId,
                                "activityLocation": al.id,
                                "start": classStart,
                                "end": classEnd,
                            }.items()
                        )
                    )
                    print("Checking:", classStart, classEnd, classHash)
                    if classHash in personalBasket:
                        classObject["bookable"] = False

                activity["times"][dayName].append(classObject)

                isClass = True
            elif auth:
                acl = db.session.query(ActivityLocation).get(al.id)
                if db.session.query(Facility).get(acl.facilityId) is not None:
                    periods = availableSlots(al.id, searchedDatetime)
                    if "slots" not in activity:
                        activity["slots"] = {}
                    activity["slots"][al.facilityId] = periods

        if isClass:
            classes.append(activity)
        else:
            activities.append(activity)

    return {
        "activities": activities,
        "classes": classes,
        "currentDate": currentDate,
        "searchedDate": searchedDate,
        "weekDayDates": weekDayDateStrings,
        "weekDayDatesPast": weekDayDatesPast,
    }


@app.route("/activities", methods=["GET", "POST"])
def activities():
    args = {
        "auth": current_user.is_authenticated,
    }
    if current_user.is_authenticated:
        args["accountId"] = current_user.id

    if current_user.is_authenticated and request.args.get("date") is not None:
        searchedDate = request.args.get("date")
        searchedDatetime = datetime.datetime.strptime(searchedDate, "%Y-%m-%d")
        args["searchedDatetime"] = searchedDatetime

    data = getActivityData(**args)
    # limit search to two weeks ahead
    data["maxDate"] = datetime.datetime.strftime(
        datetime.datetime.now() + datetime.timedelta(days=2 * 7), "%Y-%m-%d"
    )
    return render_template("activities.html", **data)


@login_required
@app.route("/user_booking", methods=["GET", "POST"])
def userBooking():
    if AccountTypeCheck() == "User":
        return redirect("/activities")
    users = Account.query.filter_by(accountType="User").all()
    args = {
        "auth": current_user.is_authenticated,
    }
    # if request.args.get("accountId") is not None:
    #     args["accountId"] = request.args.get("accountId")

    if current_user.is_authenticated and request.args.get("date") is not None:
        searchedDate = request.args.get("date")
        searchedDatetime = datetime.datetime.strptime(searchedDate, "%Y-%m-%d")
        args["searchedDatetime"] = searchedDatetime
    data = getActivityData(**args)
    data["users"] = users
    if request.args.get("accountId") is not None:
        account = db.session.query(Account).get(request.args.get("accountId"))
        data["accountId"] = account.id
        data["accountUsername"] = account.username
    return render_template("user_booking.html", **data)


def getBookings(current_user, **kwargs):
    fromTime = None
    until = None
    if "fromTime" in kwargs:
        fromTime = kwargs["fromTime"]
    if "until" in kwargs:
        until = kwargs["until"]

    bookings = (
        db.session.query(Booking)
        .filter(Booking.accountId == current_user.id)
        .order_by(Booking.start)
        .all()
    )

    activities = {
        "upcoming": {"activities": [], "classes": []},
        "past": {"activities": [], "classes": []},
    }
    now = datetime.datetime.now()
    for booking in bookings:
        if until is not None and booking.end > until:
            continue
        if fromTime is not None and booking.start < fromTime:
            continue
        acl = db.session.query(ActivityLocation).get(booking.activityLocation)
        act = db.session.query(Activity).get(acl.activityId)
        fac = db.session.query(Facility).get(acl.facilityId)
        duration = (booking.end - booking.start).total_seconds()
        hours = int(duration // 3600)
        duration -= hours * 3600
        minutes = int(duration // 60)
        durationString = ""
        if hours > 0:
            durationString += f"{hours}h"
        if minutes > 0:
            durationString += f"{minutes}m"

        activity = {
            "id": booking.id,
            "name": act.name,
            "facility": fac.name,
            "date": booking.start.strftime("%A %d/%m/%y"),
            "time": booking.start.strftime("%H:%M")
            + " - "
            + booking.end.strftime("%H:%M"),
            "duration": durationString,
        }

        if booking.end < now:
            if acl.startDay and acl.startTime:
                activities["past"]["classes"].append(activity)
            else:
                activities["past"]["activities"].append(activity)
        else:
            if acl.startDay and acl.startTime:
                activities["upcoming"]["classes"].append(activity)
            else:
                activities["upcoming"]["activities"].append(activity)

    return activities


@app.route("/bookings", methods=["GET", "POST"])
@login_required
def bookings():
    bookings = getBookings(current_user)

    membership = (
        db.session.query(Membership)
        .filter(Membership.accountId == current_user.id)
        .first()
    )

    return render_template(
        "bookings.html",
        upcomingClasses=bookings["upcoming"]["classes"],
        upcomingActivities=bookings["upcoming"]["activities"],
        pastClasses=bookings["past"]["classes"],
        pastActivities=bookings["past"]["activities"],
        membership=membership,
        user=True,
    )


@app.route("/view_user_bookings", methods=["GET", "POST"])
@login_required
def viewUserBookings():
    if AccountTypeCheck() == "User":
        return redirect("/bookings")

    users = Account.query.filter_by(accountType="User").all()
    choices = []
    for user in users:
        choices.append(user.username)

    form = SelectUser(choices=choices)

    if request.method != "POST":
        return render_template("view_user_bookings.html", form=form, users=users)

    if not form.validate_on_submit():
        logging.warning("View User Bookings: Invalid form submitted")
        return (
            render_template(
                "view_user_bookings.html",
                form=form,
                users=users,
                alert={"color": "danger", "msg": "Invalid form."},
            ),
            500,
        )

    username = form.userId.data
    user = Account.query.filter_by(username=username).first()

    membership = (
        db.session.query(Membership)
        .filter(Membership.accountId == current_user.id)
        .first()
    )

    bookings = getBookings(user)
    return render_template(
        "view_user_bookings.html",
        upcomingClasses=bookings["upcoming"]["classes"],
        upcomingActivities=bookings["upcoming"]["activities"],
        pastClasses=bookings["past"]["classes"],
        form=form,
        users=users,
        pastActivities=bookings["past"]["activities"],
        username=username,
        accountId=user.id,
        membership=membership,
        user=False,
    )


@app.route("/cancel_booking/<bookingId>", methods=["GET", "POST"])
@login_required
def cancel_booking(bookingId):
    accountId = Booking.query.get(bookingId).accountId

    redirectURL = "/bookings"
    if (
        session["accountType"] == "Manager" or session["accountType"] == "Employee"
    ) and accountId != current_user.id:
        redirectURL = "/view_user_bookings"

    booking = db.session.query(Booking).get(bookingId)
    receipt = None

    if booking.receiptId:
        receipt = db.session.query(Receipt).get(booking.receiptId)

    if (
        accountId == current_user.id
        or session["accountType"] == "Manager"
        or session["accountType"] == "Employee"
    ):
        db.session.delete(booking)
        db.session.commit()
        app.logger.info("Booking canceled")
    else:
        app.logger.info(
            "Booking cancellation failed, booking was not owned by the user"
        )
        session["alert"] = {"color": "danger", "msg": "Cancellation failed."}
        return redirect(redirectURL)

    if receipt is not None:
        refundAmount = receipt.itemPrice
        itemCount = receipt.itemCount - receipt.refundedItemCount
        refundReceiptType = "Refund"
        alert = {
            "color": "success",
            "start": "Cancelled",
            "msg": f"£{refundAmount:.2f} refunded.",
        }
        # For discounted purchases, charge full price for the uncanceled bookings, and refund the remaining money.
        if (
            receipt.refundedItemCount == 0
            and receipt.discountPct
            and receipt.discountPct > 0
            and (itemCount - 1 < 3)
        ):
            refundReceiptType = "Partial Refund"
            total = ((100 - receipt.discountPct) / 100) * (
                itemCount * float(receipt.itemPrice)
            )
            refundAmount = total - ((itemCount - 1) * float(receipt.itemPrice))
            alert[
                "msg"
            ] = f"£{refundAmount:.2f} refunded as a discount no longer applies."
            # Store that we've refunded an item so that future refunds from this purchase are for the full amount
            setattr(receipt, "refundedItemCount", receipt.refundedItemCount + 1)

        cancellationReceipt = Receipt(
            accountId=accountId,
            date=datetime.datetime.today(),
            itemCount=1,
            itemPrice=-1 * refundAmount,
            discountPct=0,
            itemName=f"{refundReceiptType}: {receipt.itemName}",
        )
        db.session.add(cancellationReceipt)

        stripe.Refund.create(
            payment_intent=receipt.stripePaymentIntentId, amount=int(refundAmount * 100)
        )

        session["alert"] = alert

        db.session.commit()

    return redirect(redirectURL)


# Check database for a valid membership, and re-verify with stripe if a subscription appears to have expired.
def checkMembership(accountId):
    today = datetime.datetime.now()
    memberships = db.session.query(Membership).filter(
        Membership.accountId == current_user.id
    )
    validMembership = False
    for membership in memberships:
        if (
            membership.startDate <= today
            and membership.endDate > today
            and membership.active
        ):
            validMembership = True
            break

    if validMembership:
        return True

    # Membership validity is only stored for the subscription period (a month or year). If it appears expired to us,
    # check with stripe if the subscription renewed succesfully and update the database if so.
    stripeUsers = stripe.Customer.search(
        query=f'metadata["accountId"]:"{accountId}"',
        limit=1,
        expand=["data.subscriptions"],
    )
    if len(stripeUsers["data"]) == 0:
        return False

    subs = stripeUsers["data"][0]["subscriptions"]["data"]
    validSubId = ""
    startDate = today
    endDate = today
    price = 0
    for sub in subs:
        if datetime.datetime.utcfromtimestamp(int(sub["current_period_end"])) > today:
            validSubId = sub["id"]
            startDate = datetime.datetime.utcfromtimestamp(
                int(sub["current_period_start"])
            )
            endDate = datetime.datetime.utcfromtimestamp(int(sub["current_period_end"]))
            price = float(sub["items"]["data"][0]["plan"]["amount"]) / 100.0
            break

    if validSubId == "":
        return False

    prod = stripe.Product.retrieve(
        stripe.Subscription.retrieve(validSubId)["plan"]["product"]
    )

    price = (
        db.session.query(MembershipPrices)
        .filter(MembershipPrices.name == prod["metadata"]["planPeriod"])
        .first()
    )
    membership = (
        db.session.query(Membership)
        .filter(
            and_(
                Membership.accountId == current_user.id,
                Membership.entryType == price.id,
            )
        )
        .first()
    )

    # Handle when app previously failed to register a successful payment
    if not membership:
        membership = Membership(
            accountId=accountId,
            entryType=price.id,
            startDate=startDate,
            endDate=endDate,
        )
        db.session.add(membership)

    setattr(membership, "endDate", endDate)
    setattr(membership, "active", True)

    r = Receipt(
        accountId=accountId,
        date=startDate,
        itemCount=1,
        discountPct=0,
        itemPrice=price.price,
    )

    if price.name == "Month":
        r.itemName = "Gold Subscription (1 Month)"
    else:
        r.itemName = "Platinum Subscription (1 Year)"

    db.session.add(r)

    logging.info(f"Updated membership validity for user {accountId}")
    db.session.commit()

    return True


@app.route(
    "/add_booking/<userId>/<classOrFacility>/<activityLocationId>/<day>",
    methods=["GET", "POST"],
)
@login_required
def add_booking(userId, classOrFacility, activityLocationId, day):
    referrer = request.args.get("referrer")
    redirectURL = "/activities"
    if referrer == "user_booking":
        redirectURL = "/user_booking"

    if classOrFacility == "class":
        activityLocation = db.session.query(ActivityLocation).get(activityLocationId)
        activity = db.session.query(Activity).get(activityLocation.activityId)
    else:
        # Some jank. Since for non-class bookings the site doesn't know the activityLocation, it sends the activity and facility IDs instead, which are used here to find the AL.
        activity = db.session.query(Activity).get(activityLocationId)
        activityLocation = (
            db.session.query(ActivityLocation)
            .filter(
                and_(
                    ActivityLocation.activityId == activity.id,
                    ActivityLocation.facilityId == classOrFacility,
                )
            )
            .first()
        )

    date = datetime.datetime.strptime(day, "%Y-%m-%d")
    endDate = date
    if classOrFacility == "class":
        # Ensure booking day actually matches the class day
        while activityLocation.startDay - 1 != date.weekday():
            date += datetime.timedelta(days=1)
        startTime = numericToTuple(activityLocation.startTime)
        date = date.replace(hour=startTime[0], minute=startTime[1])
        endDate = date + datetime.timedelta(hours=activity.length)
        if not classBookable(activityLocation.id, date, accountId=current_user.id):
            session["alert"] = {"color": "danger", "msg": "Slot no longer available."}
            return redirect(redirectURL)
    else:
        startTime = datetime.datetime.strptime(request.args.get("start"), "%H:%M")
        endTime = datetime.datetime.strptime(request.args.get("end"), "%H:%M")
        date = date.replace(hour=startTime.hour, minute=startTime.minute)
        endDate = endDate.replace(hour=endTime.hour, minute=endTime.minute)
        if not activityBookable(
            activityLocation.id, date, endDate, accountId=current_user.id
        ):
            session["alert"] = {"color": "danger", "msg": "Slot no longer available."}
            return redirect(redirectURL)

    teamEvent = "Team" in activity.name

    if (
        userId != "None"
        and current_user.accountType != AccountType.User
        and referrer != "activities"
    ):
        t = Booking(
            accountId=userId,
            activityLocation=activityLocation.id,
            start=date,
            end=endDate,
            teamBooking=teamEvent,
        )
        db.session.add(t)
        db.session.commit()

        session["alert"] = {
            "color": "success",
            "start": "Success",
            "msg": "Booking created.",
        }
        return redirect("/user_booking")

    validMembership = checkMembership(current_user.id)
    if validMembership:
        t = Booking(
            accountId=current_user.id,
            activityLocation=activityLocation.id,
            start=date,
            end=endDate,
            teamBooking=teamEvent,
        )
        db.session.add(t)
        db.session.commit()
        return redirect("/bookings")

    # add to basket
    if "basket" not in session:
        session["basket"] = []

    basket = session["basket"]
    basketItem = {
        "accountId": current_user.id,
        "activityLocation": activityLocation.id,
        "start": date.strftime("%a %d/%m/%y %H:%M"),
        "end": endDate.strftime("%H:%M"),
        "teamBooking": teamEvent,
    }
    # we need some way of recognizing each booking in the basket.
    # here we generate a temporary one, which can also be used to find duplicates quickly.
    print("Hashing:", date, endDate, end="")
    basketItem["id"] = hash(
        frozenset(
            {
                "accountId": current_user.id,
                "activityLocation": activityLocation.id,
                "start": date.replace(microsecond=0),
                "end": endDate.replace(microsecond=0),
            }.items()
        )
    )
    print(", ", basketItem["id"])

    personalBasket = list(filter(lambda bk: bk["accountId"] == current_user.id, basket))
    for item in personalBasket:
        if item["id"] == basketItem["id"]:
            session["alert"] = {
                "color": "danger",
                "start": "Failed",
                "msg": "This is already in your basket.",
            }
            return redirect("/activities")

    basket.append(basketItem)

    session["basket"] = basket

    return redirect("/checkout")

    # db.session.add(t)
    # db.session.commit()

    # return redirect("/bookings")


@app.route("/account_info", methods=["GET", "POST"])
@login_required
def accountInfo():
    # shows account infomation
    data = db.session.query(Account).get(current_user.id)
    receiptRows = (
        db.session.query(Receipt)
        .filter(Receipt.accountId == current_user.id)
        .order_by(Receipt.date.desc())
        .all()
    )
    receipts = []
    for r in receiptRows:
        if r.discountPct is None:
            r.discountPct = 0

        receipts.append(
            {
                "date": r.date.strftime("%A %D %B %Y"),
                "discountPct": r.discountPct,
                "itemName": r.itemName,
                "itemCount": r.itemCount,
                "itemPrice": r.itemPrice,
                "totalPrice": "{:.2f}".format(
                    ((100.0 - float(r.discountPct)) / 100.0)
                    * (float(r.itemPrice) * float(r.itemCount))
                ),
            }
        )

    address = (
        db.session.query(Address).filter(Address.accountId == current_user.id).first()
    )

    if address is None:
        # Empty placeholder address
        address = Address()

    # Generate receipts if necessary
    checkMembership(current_user.id)
    return render_template(
        "account_info.html", data=data, receipts=receipts, address=address
    )


@app.route("/account_info/address", methods=["PUT"])
@login_required
def changeAddress():
    newAddr = request.get_json()
    address = (
        db.session.query(Address).filter(Address.accountId == current_user.id).first()
    )
    existingAddress = address is not None
    if not existingAddress:
        address = Address(accountId=current_user.id)

    for field in ["line1", "line2", "line3", "city", "postcode", "country", "phone"]:
        if newAddr[field]:
            setattr(address, field, newAddr[field])

    if not existingAddress:
        db.session.add(address)

    db.session.commit()
    return "", 200


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def changePassword():
    form = ChangePassword()

    if request.method != "POST":
        return render_template("change_password.html", form=form)

    if not form.validate_on_submit():
        logging.warning("Change Password: Invalid form submitted")
        return (
            render_template(
                "change_password.html",
                form=form,
                alert={"color": "danger", "msg": "Invalid form."},
            ),
            500,
        )

    oldPassword = form.oldPassword.data
    newPassword = form.newPassword.data

    user = Account.query.get(current_user.id)
    if user and user.check_password(oldPassword):
        user.set_password(newPassword)
        user.generatedPassword = False
        db.session.commit()
        return render_template(
            "change_password.html",
            form=form,
            alert={"start": "Success", "msg": "Password Changed", "color": "success"},
            redirect={"url": "/login", "timeout": "2000"},
        )

    logging.warning(f"Change Password: Old password doesn't match")
    return render_template(
        "change_password.html",
        form=form,
        alert={"msg": "Old Password invalid", "color": "danger"},
    )


@app.route("/forgot_password", methods=["GET", "POST"])
def forgotPassword():
    form = ForgotPassword()

    # Redirect if we're already logged in
    if current_user.is_authenticated:
        return redirect("/")

    if request.method != "POST":
        return render_template("forgot_password.html", form=form)

    if not form.validate_on_submit():
        logging.warning("Forgot Password: Invalid form submitted")
        return (
            render_template(
                "forgot_password.html",
                form=form,
                alert={"color": "danger", "msg": "Invalid form."},
            ),
            500,
        )

    email = form.email.data

    user = Account.query.filter_by(email=email).first()
    if user:
        # changes password
        characters = string.ascii_letters + "0123456789"
        password = str("".join(random.choice(characters) for i in range(10)))
        user.set_password(password)
        user.generatedPassword = True
        db.session.commit()
        # creates email
        msg = Message(
            "New Password",
            sender="robotmail2000@gmail.com",
            recipients=[form.email.data],
        )
        msg.body = (
            "Your username: "
            + user.username
            + "\r\nYour new password: "
            + password
            + "\r\nPlease change your password when you have logged in."
        )
        # Sends there new password to their email
        mail.send(msg)
        app.logger.info("{} forgot password, sent email".format(user.username))
        return render_template(
            "forgot_password.html",
            form=form,
            alert={"start": "Success", "msg": "Email Sent", "color": "success"},
            redirect={"url": "/login", "timeout": "3000"},
        )
    return render_template(
        "forgot_password.html",
        form=form,
        alert={"msg": "Invalid Email", "color": "danger"},
    )


# Cancel Membership
@app.route("/cancel_membership", methods=["GET", "POST"])
@login_required
def cancelMembership():
    form = CancelMembership()

    if request.method == "POST":
        if form.validate_on_submit():
            # Get the user
            user = Account.query.get(current_user.id)
            # Get the membership
            membership = Membership.query.get(user.id)
            # Set the membership to inactive
            membership.active = False
            # Set the cancellation reason
            membership.cancellationReason = form.description.data
            # Set Cancellation Date
            membership.cancellationDate = datetime.datetime.now()
            # Commit the changes
            db.session.commit()

            # Cancel membership on stripe

            stripeUsers = stripe.Customer.search(
                query=f'metadata["accountId"]:"{user.id}"',
                limit=1,
                expand=["data.subscriptions"],
            )

            # If the user doesn't have a stripe account, return false
            if len(stripeUsers["data"]) == 0:
                return False

            stripe.Subscription.delete(
                stripeUsers["data"][0]["subscriptions"]["data"][0]["id"]
            )

            # Redirect to the login page
            return render_template(
                "cancel_membership.html",
                form=form,
                alert={
                    "start": "Success",
                    "msg": "Membership Cancelled",
                    "color": "success",
                },
                redirect={"url": "/", "timeout": "2000"},
            )

    return render_template("cancel_membership.html", form=form)


@app.route("/facilities/<facilityId>/capacity", methods=["GET"])
# facilityCurrentCapacity returns an estimate of the number of people
# currently in <facilityId>. If <facilityId> == "all", estimate is
# for the whole gym.
# if the facility is closed, "open" = false is returned and remaining
# is set to zero.
def facilityCurrentCapacity(facilityId):
    today = datetime.datetime.now().replace(second=0, microsecond=0)
    time = timeToNumeric(datetime.datetime.now().strftime("%H:%M"))
    facilities = []
    if facilityId == "all":
        facilities = db.session.query(Facility).all()
    else:
        facilities = [db.session.query(Facility).get(facilityId)]

    facilityCapacities = [f.capacity for f in facilities]
    facilityRemainings = [f.capacity for f in facilities]

    facilityOpen = len(facilities)
    for f in facilities:
        if not (time > f.opens and time < f.closes):
            facilityOpen -= 1

    facilityOpen = facilityOpen > 0
    if not facilityOpen:
        facilityRemainings = [0]
    else:
        aclFilters = [(ActivityLocation.facilityId == f.id) for f in facilities]
        activityLocations = [
            db.session.query(ActivityLocation).filter(f).all() for f in aclFilters
        ]
        bookingFilters = [
            [(Booking.activityLocation == acl.id) for acl in acls]
            for acls in activityLocations
        ]
        bookings = [
            db.session.query(Booking).filter(or_(*filters)).all()
            for filters in bookingFilters
        ]

        for i, facilityBookings in enumerate(bookings):
            for booking in facilityBookings:
                if booking.start <= today and booking.end >= today:
                    facilityRemainings[i] -= 1

    return (
        jsonify(
            {
                "capacity": sum(facilityCapacities),
                "remaining": sum(facilityRemainings),
                "open": facilityOpen,
            }
        ),
        200,
    )


@app.route("/<path:path>")
# Static Proxy delivers files from the "app/static" folder.
def StaticProxy(path):
    return app.send_static_file(path)
