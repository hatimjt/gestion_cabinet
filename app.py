import datetime
from os import path
from time import sleep
from random import randint, randrange, choice
from flask import Flask, jsonify, render_template, url_for, request, redirect, Blueprint, flash , session
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from wtforms import Form, BooleanField, StringField, PasswordField, RadioField, validators
from sqlalchemy.sql import text


app = Flask(__name__)
app.config['SECRET_KEY']= 'secret1234567890'
DB_NAME = 'cabmeds.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}' f strings do not exist in older versions
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_NAME
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost:5432/medical_cabinet'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)




#############################################################
#                                                           #
#     #     #                                               #
#     ##   ##   ####   #####   ######  #        ####        #
#     # # # #  #    #  #    #  #       #       #            #
#     #  #  #  #    #  #    #  #####   #        ####        #
#     #     #  #    #  #    #  #       #            #       #
#     #     #  #    #  #    #  #       #       #    #       #
#     #     #   ####   #####   ######  ######   ####        #
#                                                           #
#############################################################



# table definitions
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    user_type = db.Column(db.String(8), unique=False, nullable=False) # -> admin, customer, owner, agent
    name = db.Column(db.String(255), unique=False, nullable=False)
    surname = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    max_rent = db.Column(db.String(255), unique=False, nullable=False)


class VisitingList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('users.id', onupdate="CASCADE", ondelete="CASCADE"))
    # userId = db.Column(db.Integer, unique=False, nullable=False)
    propertiesList = db.Column(db.PickleType)


class Properties(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), unique=False, nullable=False)
    address = db.Column(db.String(255), unique=False, nullable=False)
    owner = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=False)
    phone = db.Column(db.String(255), unique=False, nullable=False)
    price = db.Column(db.String(255), unique=False, nullable=False)
    pet_friendly = db.Column(db.String(255), unique=False, nullable=False)


#############################################################
#                                                           #
#         #######                                           #
#         #         ####   #####   #    #   ####            #
#         #        #    #  #    #  ##  ##  #                #
#         #####    #    #  #    #  # ## #   ####            #
#         #        #    #  #####   #    #       #           #
#         #        #    #  #   #   #    #  #    #           #
#         #         ####   #    #  #    #   ####            #
#                                                           #
#############################################################

class AccountForm(Form):
    username = StringField('UserName', [validators.Length(min=1, max=50)])
    name = StringField('Name', [validators.Length(min=1, max=50)])
    surname = StringField('Surname', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=5, max=50)])
    password = PasswordField('New Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm  = PasswordField('Repeat Password')
    user_type = RadioField('user_type', choices=[('customer','Customer'),('owner','Owner'),('agent','Agent')])
    max_rent = StringField('maxRent', [validators.Length(min=1, max=10)])

    # validators.DataRequired() / InputRequired()


class PropertyForm(Form):
    description = StringField('description', [validators.Length(min=1, max=50)])
    address = StringField('address', [validators.Length(min=1, max=50)])
    owner = StringField('owner', [validators.Length(min=1, max=50)])
    email = StringField('email', [validators.Length(min=1, max=50)])
    phone = StringField('phone', [validators.Length(min=1, max=50)])
    price = StringField('price', [validators.Length(min=1, max=50)])
    pet_friendly = RadioField('pet_friendly', choices=[('yes','Yes'),('no','No')])
    # validators.DataRequired() / InputRequired()





#############################################################
#                                                           #
#        ######                                             #
#        #     #   ####   #    #  #####  ######   ####      #
#        #     #  #    #  #    #    #    #       #          #
#        ######   #    #  #    #    #    #####    ####      #
#        #   #    #    #  #    #    #    #            #     #
#        #    #   #    #  #    #    #    #       #    #     #
#        #     #   ####    ####     #    ######   ####      #
#                                                           #
#############################################################

@app.context_processor
def inject_user():
    return dict(user=current_user)

seed_button_disabled = False

@app.context_processor
def inject_seed_button_state():
    global seed_button_disabled
    if seed_button_disabled:
        return dict(seed_button_disabled=True)
    else:
        return dict(seed_button_disabled=False)

auth = Blueprint('auth', 'auth')

login_manager = LoginManager()
#print(url_for('auth.login'))
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id)) # looks for PK by default







# @app.before_request
# def before_request():
#     print(request.endpoint)


@app.route('/', methods = ['GET'])
def index():
    # if went to 127.0.0.1:8080 for the first time, create the admin account
    does_not_exist = db.session.query(Users.email).filter_by(email='admin@cabmed').first() is None
    if does_not_exist:



        admin = Users(user_type='admin', username = 'admin', name='admin', surname='admin', email='admin@cabmed', password=generate_password_hash("password", method='sha256'), max_rent='1000$')
        adminVL = VisitingList(userId= 1, propertiesList=[] )
        sparky = Users(user_type='Agent', username = 'sparky', name='sparky', surname='onlive', email='sparky@cabmed', password=generate_password_hash("password", method='sha256'), max_rent='1000$')
        sparkyVL = VisitingList(userId= 2, propertiesList=[] )
        tuta = Users(user_type='Owner', username='tuta', name='tuta', surname='nota', email='tuta@cabmed', password=generate_password_hash("password", method='sha256'), max_rent='1000$')
        tutaVL = VisitingList(userId= 3, propertiesList=[] )
        jado = Users(user_type='Customer', username='jado', name='jado', surname='lpikos', email='jado@cabmed', password=generate_password_hash("password", method='sha256'), max_rent='1000$')
        jadoVL = VisitingList(userId= 4, propertiesList=[] )
        oxy = Users(user_type='Owner', username='oxy', name='oxy', surname='doxy', email='oxy@cabmed', password=generate_password_hash("password", method='sha256'), max_rent='1000$')
        oxyVL = VisitingList(userId= 5, propertiesList=[] )
        hatim = Users(user_type='Customer', username='hatim', name='hatim', surname='jt', email='hatim@cabmed', password=generate_password_hash("password", method='sha256'), max_rent='1000$')
        hatimVL = VisitingList(userId= 6, propertiesList=[1,2] )

        db.session.add(admin)
        db.session.add(sparky)
        db.session.add(tuta)
        db.session.add(jado)
        db.session.add(oxy)
        db.session.add(hatim)
        db.session.commit()

        db.session.add(adminVL)
        db.session.add(sparkyVL)
        db.session.add(tutaVL)
        db.session.add(jadoVL)
        db.session.add(oxyVL)
        db.session.add(hatimVL)
        db.session.commit()


        propertya = Properties(description='2 bedroom appartment all inclusive', address='rabatlagdal',  owner='oxy',  email='oxy@cabmed',  phone='0662485142', price='850', pet_friendly="yes")
        propertyb = Properties(description='1 bedroom + wifi', address='kech',  owner='tuta',  email='tuta@cabmed',  phone='0662154723', price='440', pet_friendly="no")
        propertyc = Properties(description='studio/bachelor basement', address='temara',  owner='oxy',  email='oxy@cabmed',  phone='0662154724', price='720', pet_friendly="yes")
        propertyd = Properties(description='3 bedroom appartment + den', address='temara',  owner='tuta',  email='tuta@cabmed',  phone='0662154726', price='1480', pet_friendly="yes")

        db.session.add(propertya)
        db.session.add(propertyb)
        db.session.add(propertyc)
        db.session.add(propertyd)
        db.session.commit()


        # hatimVL = VisitingList(userId= 6, propertiesList=[1,2] )
        # print(hatimVL)
        # print("the user ID is: ", hatimVL.userId)
        # hatimVL.propertiesList.append(4)
        # print("the properties list is: ", hatimVL.propertiesList)
        # db.session.add(hatimVL)
        # db.session.commit()



        print("property committed")

        # do not log in automatically
        logout_user()

    return render_template('index.html', user = current_user)

#Admin & Authentication
@app.route('/admin', methods = ['GET'])
@login_required
def admin():
    if current_user.user_type == "admin":
        try:
            users = list()
            response = db.session.execute(text('SELECT * FROM users;'))
            for r in response:
                row = list()
                for x in range(len(r)):
                    row.append(r[x])
                users.append(row)
        except Exception as error:
            print(error)
            return render_template('admin.html', error=str(error))
        finally:
            db.session.commit()
        return render_template('admin.html', users=users)
    else:
        flash('You are not an admin', category='error')
        return redirect('/')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in!', category='error')
        return redirect('/')
    else:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = Users.query.filter_by(username=username).first()
            if user:
                if check_password_hash(user.password, password):
                    login_user(user, remember=True)
                    print('Logged in successfully!')
                    flash('Logged in successfully!', category='success')
                    # return the page according to the 'next' tag
                    next = request.args.get('next')
                    return redirect(next or '/')
                else:
                    print('Incorrect password!')
                    flash('Incorrect password!', category='error')
            else:
                print('User does not exist!')
                flash('User does not exist!', category='error')
        return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are now logged out!', category='error')
    return redirect('/login')

app.register_blueprint(auth, url_prefix='/')


#Accounts

@app.route('/createaccount', methods = ['GET', 'POST'])
def createaccount():
    if current_user.is_authenticated:
        flash('To create an account logout first.', category='error')
        return redirect('/')
    else:
        form = AccountForm(request.form)
        if request.method == 'POST' and form.validate():
            user = Users(user_type=form.user_type.data, username=form.username.data, max_rent=form.max_rent.data, name=form.name.data, surname=form.surname.data, email=form.email.data, password=generate_password_hash(form.password.data, method='sha256'))
            db.session.add(user)
            db.session.commit()
            newUserVL = VisitingList(userId= user.id, propertiesList=[] )

            # do not log in automatically
            logout_user()
            flash('Thanks for registering')
            # return redirect(url_for('login'))
            # return render_template('createaccount.html', form=form)
            return redirect('/login')
        elif request.method == 'POST' and not form.validate():
            flash('Input error.. try again!', category='error')
        return render_template('createaccount.html', form=form)

@app.route('/viewaccount', methods = ['GET'])
def viewaccount():
    if current_user.is_authenticated:
        return render_template('viewaccount.html', name=current_user.name, email=current_user.email, id=current_user.id, surname=current_user.surname, user_type=current_user.user_type, username=current_user.username)
    else:
        print('Please login first!')
        flash('Please login first!', category='error')
    return render_template('login.html')

@app.route('/updateaccount', methods = ['GET', 'POST'])
def updateaccount():
    if current_user.is_authenticated :
        if current_user.user_type == "admin":
            form = AccountForm(request.form)
            if request.method == 'POST' and form.validate():
                user = Users.query.get(current_user.id)
                # user.username = form.username.data
                # user.user_type=form.user_type.data
                # user.name=form.name.data
                # user.surname=form.surname.data
                # user.max_rent=form.max_rent.data

                user.username = current_user.username
                user.user_type=current_user.user_type
                user.name=current_user.name
                user.surname=current_user.surname
                user.max_rent=current_user.max_rent

                user.email=form.email.data
                user.password=generate_password_hash(form.password.data, method='sha256')
                db.session.commit()
                # do not log in automatically
                flash('Thanks for updating')
                # return redirect(url_for('login'))
                # return render_template('createaccount.html', form=form)
                return redirect('/viewaccount')
            elif request.method == 'POST' and not form.validate():
                flash('Input error.. try again!', category='error')
            return render_template('updateaccount.html', form=form, old_username=current_user.username, old_max_rent=current_user.max_rent, old_name=current_user.name, old_email=current_user.email, old_surname=current_user.surname, old_user_type=current_user.user_type)
            # return render_template('updateaccount.html', form=form, old_email=current_user.email)
        else:
            flash('unauthoized access', category='error')
            return redirect('/')
    else:
        flash('To edit an account login first.', category='error')
        return redirect('/login')

@app.route('/deleteaccount', methods = ['GET','POST'])
def deleteaccount():
    if current_user.is_authenticated:
        user = Users.query.get(current_user.id)
        # user.user_type=form.user_type.data
        # user.name=form.name.data
        # user.surname=form.surname.data
        # user.email=form.email.data
        # user.password=generate_password_hash(form.password.data, method='sha256')
        # user.max_rent='False'
        db.session.delete(user)
        db.session.commit()
        # do not log in automatically
        flash('Your account was successfully deleted')
        # return redirect(url_for('login'))
        # return render_template('createaccount.html', form=form)
        return redirect('/')
    else:
        flash('To delete an account login first.', category='error')
        return redirect('/')

#Properties

@app.route('/property/<id>', methods = ['GET', 'POST'])
def property(id):
    propertya = Properties.query.get(id)

    response = db.session.execute(text('SELECT * FROM properties;'))
    # print("the response hia:")
    print(propertya.address)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     properties.append(row)
    return render_template('property.html', id=propertya.id, description=propertya.description, address=propertya.address,  owner=propertya.owner,  email=propertya.email,  phone=propertya.phone, price=propertya.price, pet_friendly=propertya.pet_friendly)

@app.route('/createproperty', methods = ['GET', 'POST'])
def createproperty():
    form = PropertyForm(request.form)
    if request.method == 'POST' and form.validate():
        property = Properties(description=form.description.data, address=form.address.data,  owner=form.owner.data,  email=form.email.data,  phone=form.phone.data, price=form.price.data, pet_friendly=form.pet_friendly.data)
        db.session.add(property)
        db.session.commit()
        # do not log in automatically
        flash('Thanks for adding the property')
        # return redirect(url_for('login'))
        # return render_template('createaccount.html', form=form)
        return redirect('/viewproperties')
    elif request.method == 'POST' and not form.validate():
        flash('Input error.. try again!', category='error')
    return render_template('createproperty.html', form=form)

@app.route('/updateproperty/<id>', methods = ['GET', 'POST'])
def updateproperty(id):
    form = PropertyForm(request.form)
    propertya = Properties.query.get(id)

    if request.method == 'POST' and form.validate():
        propertya.description=form.description.data
        propertya.address=form.address.data
        propertya.owner=form.owner.data
        propertya.email=form.email.data
        propertya.phone=form.phone.data
        propertya.price=form.price.data
        propertya.pet_friendly=form.pet_friendly.data
        db.session.commit()
        # do not log in automatically
        flash('Thanks for updating the property')
        # return redirect(url_for('login'))
        # return render_template('createaccount.html', form=form)
        return redirect('/viewaccount')
    elif request.method == 'POST' and not form.validate():
        flash('Input error.. try again!', category='error')
    return render_template('updateproperty.html', form=form,  old_id=propertya.id, old_description=propertya.description, old_address=propertya.address,  old_owner=propertya.owner,  old_email=propertya.email,  old_phone=propertya.phone, old_price=propertya.price, old_pet_friendly=propertya.pet_friendly)


@app.route('/viewproperties', methods = ['GET'])
def viewproperties():
    properties = list()
    response = db.session.execute(text('SELECT * FROM properties;'))
    print("the response hia:")
    print(response)
    for record in response:
        print("l item d response houa")
        print(record)
        print(record.description)
        # row = list()
        # for x in range(len(r)):
        #     row.append(r[xI)
        properties.append(record)
    return render_template('viewproperties.html', properties=properties)
    # if current_user.is_authenticated:
    #     return render_template('viewproperty.html', property=)
    # else:
    #     print('Please login first!')
    #     flash('Please login first!', category='error')
    # return render_template('login.html')

@app.route('/viewpropertiesbylocation/<location>', methods = ['GET'])
def viewpropertiesbylocation(location):
    properties = list()
    response = Properties.query.filter(Properties.address.contains(location))
    # response = db.session.execute('SELECT * FROM properties;')
    print("the response hia:")
    print(response)

    for record in response:
        print("l item d response houa")
        print(record)
        print(record.address)
        properties.append(record)
    #     properties.append(record)
        # row = list()
        # for x in range(len(record)):
        #     row.append(record[x])
        # properties.append(row)
        # print(properties)
    if len(properties)==0:
        flash('No properties found at this location.', category='error')
    return render_template('viewproperties.html', properties=properties)
    # if current_user.is_authenticated:
    #     return render_template('viewproperty.html', property=)
    # else:
    #     print('Please login first!')
    #     flash('Please login first!', category='error')
    # return render_template('login.html')


@app.route('/deleteproperty/<id>', methods = ['GET', 'POST'])
def deleteproperty(id):
    propertya = Properties.query.get(id)
    db.session.delete(propertya)
    db.session.commit()
    # do not log in automatically
    flash('the property was successfully deleted')
    # return redirect(url_for('login'))
    # return render_template('createaccount.html', form=form)
    return redirect('/')



@app.route('/viewvisitinglist/<id>', methods = ['GET', 'POST'])
def viewvisitinglist(id):

    response = VisitingList.query.filter_by(userId=id).first()
    chkoun_hada = Users.query.get(id)
    print("chkoun hada? ")
    print(chkoun_hada.name)

    print("the response hia:")
    print(response)
    print(response.propertiesList)
    visitingList = list()
    print("the response hia:")
    print(response)
    for propertyId in response.propertiesList:
        print(propertyId)
        visitingList.append(Properties.query.get(propertyId))
    print(visitingList)
    return render_template('viewproperties.html', properties=visitingList)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     properties.append(row)
    # return redirect('/')


@app.route('/addtovisitinglist/<id>', methods = ['GET', 'POST'])
def addtovisitinglist(id):

    current_user_list = VisitingList.query.get(current_user.id)
    print(current_user_list)
    print("list before appending")
    print(current_user_list.propertiesList)
    print("list after copying")
    tmp = []
    for propertyId in current_user_list.propertiesList:
        tmp.append(propertyId)
    print(tmp)
    print("list after appending")

    tmp.append(int(id))
    print(tmp)
    current_user_list.propertiesList = tmp
    print(current_user_list.propertiesList)
    db.session.commit()

    # print("the response hia:")
    # print(response.propertiesList)
    # visitingList = list()
    # print("the response hia:")
    # print(response)
    # for propertyId in response.propertiesList:
    #     print(propertyId)
    #     visitingList.append(Properties.query.get(propertyId))
    # print(visitingList)
    # return render_template('viewproperties.html', properties=visitingList)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     properties.append(row)
    flash('Property added to visiting list', category='success')

    return redirect('/viewproperties')



@app.route('/removefromvisitinglist/<id>', methods = ['GET', 'POST'])
def removefromvisitinglist(id):

    current_user_list = VisitingList.query.get(current_user.id)
    print(current_user_list)
    print("list before appending")
    print(current_user_list.propertiesList)
    print("list after copying")
    tmp = []
    for propertyId in current_user_list.propertiesList:
        tmp.append(propertyId)
    print(tmp)
    print("list after appending")

    tmp.remove(int(id))
    print(tmp)
    current_user_list.propertiesList = tmp
    print(current_user_list.propertiesList)
    db.session.commit()

    # print("the response hia:")
    # print(response.propertiesList)
    # visitingList = list()
    # print("the response hia:")
    # print(response)
    # for propertyId in response.propertiesList:
    #     print(propertyId)
    #     visitingList.append(Properties.query.get(propertyId))
    # print(visitingList)
    # return render_template('viewproperties.html', properties=visitingList)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     properties.append(row)
    return redirect('/viewvisitinglist/'+str(current_user.id))


#############################################################
#                                                           #
#                   #     ######   ######                   #
#                  # #    #     #  #     #                  #
#                 #   #   #     #  #     #                  #
#                #     #  ######   ######                   #
#                #######  #        #                        #
#                #     #  #        #                        #
#                #     #  #        #                        #
#                                                           #
#############################################################


if __name__ == '__main__':
    DEBUG = True
    if DEBUG:
        app.debug = True
    else:
        app.debug = False

    try:
        dir_path = path.dirname(path.realpath(__file__))
        if not path.exists(dir_path + '/' + DB_NAME):
            with app.app_context():
                db.create_all()
            print('Created database and tables succesfully!')
        else:
            print('Database already exists!')
    except Exception as error:
        print(error)

    port = 6969 # the custom port you want
    app.run(host='127.0.0.1', port=port)



#############################################################
#                #     #                                    #
#                ##   ##      ####    ####                  #
#                # # # #  #  #       #    #                 #
#                #  #  #      ####   #                      #
#                #     #  #       #  #                      #
#                #     #  #  #    #  #    #                 #
#                #     #  #   ####    ####                  #
#############################################################


def select_email(l):
    return choice(l)

def generate_name(l):
    return choice(l)

