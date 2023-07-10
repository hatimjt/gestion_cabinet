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
    user_type = db.Column(db.String(255), unique=False, nullable=False) # -> admin, customer, doctor, assistant
    name = db.Column(db.String(255), unique=False, nullable=False)
    surname = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    allocation_max = db.Column(db.String(255), unique=False, nullable=False)


class Facture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, db.ForeignKey('users.id', onupdate="CASCADE", ondelete="CASCADE"))
    # userId = db.Column(db.Integer, unique=False, nullable=False)
    servicesList = db.Column(db.PickleType)


class Services(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), unique=False, nullable=False)
    address = db.Column(db.String(255), unique=False, nullable=False)
    doctor = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=False)
    phone = db.Column(db.String(255), unique=False, nullable=False)
    price = db.Column(db.String(255), unique=False, nullable=False)
    ramed = db.Column(db.String(255), unique=False, nullable=False)


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
    user_type = RadioField('user_type', choices=[('customer','Customer'),('doctor','Doctor'),('assistant','Assistant')])
    allocation_max = StringField('allocationmax', [validators.Length(min=1, max=10)])

    # validators.DataRequired() / InputRequired()


class ServiceForm(Form):
    description = StringField('description', [validators.Length(min=1, max=50)])
    address = StringField('address', [validators.Length(min=1, max=50)])
    doctor = StringField('doctor', [validators.Length(min=1, max=50)])
    email = StringField('email', [validators.Length(min=1, max=50)])
    phone = StringField('phone', [validators.Length(min=1, max=50)])
    price = StringField('price', [validators.Length(min=1, max=50)])
    ramed = RadioField('ramed', choices=[('yes','Yes'),('no','No')])
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



        admin = Users(user_type='admin', username = 'admin', name='admin', surname='admin', email='admin@cabmed', password=generate_password_hash("password", method='sha256'), allocation_max='1000$')
        adminVL = Facture(userId= 1, servicesList=[] )
        sparky = Users(user_type='assistant', username = 'sparky', name='sparky', surname='onlive', email='sparky@cabmed', password=generate_password_hash("password", method='sha256'), allocation_max='1000$')
        sparkyVL = Facture(userId= 2, servicesList=[] )
        tuta = Users(user_type='doctor', username='tuta', name='tuta', surname='nota', email='tuta@cabmed', password=generate_password_hash("password", method='sha256'), allocation_max='1000$')
        tutaVL = Facture(userId= 3, servicesList=[] )
        jado = Users(user_type='customer', username='jado', name='jado', surname='lpikos', email='jado@cabmed', password=generate_password_hash("password", method='sha256'), allocation_max='1000$')
        jadoVL = Facture(userId= 4, servicesList=[] )
        oxy = Users(user_type='Doctor', username='oxy', name='oxy', surname='doxy', email='oxy@cabmed', password=generate_password_hash("password", method='sha256'), allocation_max='1000$')
        oxyVL = Facture(userId= 5, servicesList=[] )
        hatim = Users(user_type='customer', username='hatim', name='hatim', surname='jt', email='hatim@cabmed', password=generate_password_hash("password", method='sha256'), allocation_max='1000$')
        hatimVL = Facture(userId= 6, servicesList=[1,2] )

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


        servicea = Services(description='consultation', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662485142', price='30', ramed="yes")
        serviceb = Services(description='doliprane', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154723', price='20', ramed="no")
        servicec = Services(description='x-ray', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154724', price='720', ramed="yes")
        serviced = Services(description='analyse sanguine', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154726', price='200', ramed="yes")
        servicee = Services(description='rappel de controle', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154726', price='0', ramed="yes")
        servicef = Services(description='kenta', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154726', price='100', ramed="yes")
        serviceg = Services(description='analyse vasculaire', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154726', price='150', ramed="yes")
        serviceh = Services(description='analyse generale', address='cabmedigi',  doctor='admin',  email='admin@cabmed',  phone='0662154722', price='120', ramed="yes")

        db.session.add(servicea)
        db.session.add(serviceb)
        db.session.add(servicec)
        db.session.add(serviced)
        db.session.add(servicee)
        db.session.add(servicef)
        db.session.add(serviceg)
        db.session.add(serviceh)
        db.session.commit()


        # hatimVL = Facture(userId= 6, servicesList=[1,2] )
        # print(hatimVL)
        # print("the user ID is: ", hatimVL.userId)
        # hatimVL.servicesList.append(4)
        # print("the services list is: ", hatimVL.servicesList)
        # db.session.add(hatimVL)
        # db.session.commit()



        print("service committed")

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
            user = Users(user_type=form.user_type.data, username=form.username.data, allocation_max=form.allocation_max.data, name=form.name.data, surname=form.surname.data, email=form.email.data, password=generate_password_hash(form.password.data, method='sha256'))
            db.session.add(user)
            db.session.commit()
            newUserVL = Facture(userId= user.id, servicesList=[] )

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

@app.route('/updateaccount/<id>', methods = ['GET', 'POST'])
def updateaccount(id):
    if current_user.is_authenticated :
        if current_user.user_type == "admin":
            form = AccountForm(request.form)
            user_selected = Users.query.get(id)
            if request.method == 'POST' and form.validate():
                user = Users.query.get(id)
                user.username = form.username.data
                user.user_type=form.user_type.data
                user.name=form.name.data
                user.surname=form.surname.data
                user.allocation_max=form.allocation_max.data

                # user.username = current_user.username
                # user.user_type= current_user.user_type
                # user.name= current_user.name
                # user.surname= current_user.surname
                # user.allocation_max= current_user.allocation_max

                user.email=form.email.data
                user.password=generate_password_hash(form.password.data, method='sha256')
                db.session.commit()
                # do not log in automatically
                flash('Thanks for updating')
                # return redirect(url_for('login'))
                # return render_template('createaccount.html', form=form)
                return redirect('/admin')
            elif request.method == 'POST' and not form.validate():
                flash('Input error.. try again!', category='error')
            return render_template('updateaccount.html', form=form, old_username=user_selected.username, old_allocation_max=user_selected.allocation_max, old_name=user_selected.name, old_email=user_selected.email, old_surname=user_selected.surname, old_user_type=user_selected.user_type)
            # return render_template('updateaccount.html', form=form, old_email=current_user.email)
        else:
            flash('unauthoized access', category='error')
            return redirect('/')
    else:
        flash('To edit an account login first.', category='error')
        return redirect('/login')

@app.route('/deleteaccount/<id>', methods = ['GET','POST'])
def deleteaccount(id):
    if current_user.is_authenticated:
        if current_user.user_type == "admin":
            user = Users.query.get(id)
            # user.user_type=form.user_type.data
            # user.name=form.name.data
            # user.surname=form.surname.data
            # user.email=form.email.data
            # user.password=generate_password_hash(form.password.data, method='sha256')
            # user.allocation_max='False'
            db.session.delete(user)
            db.session.commit()
            # do not log in automatically
            flash('Your account was successfully deleted')
            # return redirect(url_for('login'))
            # return render_template('createaccount.html', form=form)
            return redirect('/admin')
        else:
            flash('unauthoized access', category='error')
            return redirect('/')
    else:
        flash('To delete an account login first.', category='error')
        return redirect('/login')

#Services

@app.route('/service/<id>', methods = ['GET', 'POST'])
def service(id):
    servicea = Services.query.get(id)

    response = db.session.execute(text('SELECT * FROM services;'))
    # print("the response hia:")
    print(servicea.address)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     services.append(row)
    return render_template('service.html', id=servicea.id, description=servicea.description, address=servicea.address,  doctor=servicea.doctor,  email=servicea.email,  phone=servicea.phone, price=servicea.price, ramed=servicea.ramed)

@app.route('/createservice', methods = ['GET', 'POST'])
def createservice():
    form = ServiceForm(request.form)
    if request.method == 'POST' and form.validate():
        service = Services(description=form.description.data, address=form.address.data,  doctor=form.doctor.data,  email=form.email.data,  phone=form.phone.data, price=form.price.data, ramed=form.ramed.data)
        db.session.add(service)
        db.session.commit()
        # do not log in automatically
        flash('Thanks for adding the service')
        # return redirect(url_for('login'))
        # return render_template('createaccount.html', form=form)
        return redirect('/viewservices')
    elif request.method == 'POST' and not form.validate():
        flash('Input error.. try again!', category='error')
    return render_template('createservice.html', form=form)

@app.route('/updateservice/<id>', methods = ['GET', 'POST'])
def updateservice(id):
    form = ServiceForm(request.form)
    servicea = Services.query.get(id)

    if request.method == 'POST' and form.validate():
        servicea.description=form.description.data
        servicea.address=form.address.data
        servicea.doctor=form.doctor.data
        servicea.email=form.email.data
        servicea.phone=form.phone.data
        servicea.price=form.price.data
        servicea.ramed=form.ramed.data
        db.session.commit()
        # do not log in automatically
        flash('Thanks for updating the service')
        # return redirect(url_for('login'))
        # return render_template('createaccount.html', form=form)
        return redirect('/viewaccount')
    elif request.method == 'POST' and not form.validate():
        flash('Input error.. try again!', category='error')
    return render_template('updateservice.html', form=form,  old_id=servicea.id, old_description=servicea.description, old_address=servicea.address,  old_doctor=servicea.doctor,  old_email=servicea.email,  old_phone=servicea.phone, old_price=servicea.price, old_ramed=servicea.ramed)


@app.route('/viewservices', methods = ['GET'])
def viewservices():
    services = list()
    response = db.session.execute(text('SELECT * FROM services;'))
    print("the response hia:")
    print(response)
    for record in response:
        print("l item d response houa")
        print(record)
        print(record.description)
        # row = list()
        # for x in range(len(r)):
        #     row.append(r[xI)
        services.append(record)
    return render_template('viewservices.html', services=services)
    # if current_user.is_authenticated:
    #     return render_template('viewservice.html', service=)
    # else:
    #     print('Please login first!')
    #     flash('Please login first!', category='error')
    # return render_template('login.html')

# @app.route('/viewservicesbylocation/<location>', methods = ['GET'])
# def viewservicesbylocation(location):
#     services = list()
#     response = Services.query.filter(Services.address.contains(location))
#     # response = db.session.execute('SELECT * FROM services;')
#     print("the response hia:")
#     print(response)

#     for record in response:
#         print("l item d response houa")
#         print(record)
#         print(record.address)
#         services.append(record)
#     #     services.append(record)
#         # row = list()
#         # for x in range(len(record)):
#         #     row.append(record[x])
#         # services.append(row)
#         # print(services)
#     if len(services)==0:
#         flash('No services found at this location.', category='error')
#     return render_template('viewservices.html', services=services)
#     # if current_user.is_authenticated:
#     #     return render_template('viewservice.html', service=)
#     # else:
#     #     print('Please login first!')
#     #     flash('Please login first!', category='error')
#     # return render_template('login.html')


@app.route('/deleteservice/<id>', methods = ['GET', 'POST'])
def deleteservice(id):
    servicea = Services.query.get(id)
    db.session.delete(servicea)
    db.session.commit()
    # do not log in automatically
    flash('the service was successfully deleted')
    # return redirect(url_for('login'))
    # return render_template('createaccount.html', form=form)
    return redirect('/')



@app.route('/viewfacture/<id>', methods = ['GET', 'POST'])
def viewfacture(id):

    response = Facture.query.filter_by(userId=id).first()
    chkoun_hada = Users.query.get(id)
    print("chkoun hada? ")
    print(chkoun_hada.name)

    print("the response hia:")
    print(response)
    print(response.servicesList)
    faCture = list()
    print("the response hia:")
    print(response)
    for serviceId in response.servicesList:
        print(serviceId)
        faCture.append(Services.query.get(serviceId))
    print(faCture)
    return render_template('viewservices.html', services=faCture)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     services.append(row)
    # return redirect('/')


@app.route('/addtofacture/<id>', methods = ['GET', 'POST'])
def addtofacture(id):

    current_user_list = Facture.query.get(current_user.id)
    print(current_user_list)
    print("list before appending")
    print(current_user_list.servicesList)
    print("list after copying")
    tmp = []
    for serviceId in current_user_list.servicesList:
        tmp.append(serviceId)
    print(tmp)
    print("list after appending")

    tmp.append(int(id))
    print(tmp)
    current_user_list.servicesList = tmp
    print(current_user_list.servicesList)
    db.session.commit()

    # print("the response hia:")
    # print(response.servicesList)
    # faCture = list()
    # print("the response hia:")
    # print(response)
    # for serviceId in response.servicesList:
    #     print(serviceId)
    #     faCture.append(Services.query.get(serviceId))
    # print(faCture)
    # return render_template('viewservices.html', services=faCture)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     services.append(row)
    flash('Service added to facture', category='success')

    return redirect('/viewservices')



@app.route('/removefromfacture/<id>', methods = ['GET', 'POST'])
def removefromfacture(id):

    current_user_list = Facture.query.get(current_user.id)
    print(current_user_list)
    print("list before appending")
    print(current_user_list.servicesList)
    print("list after copying")
    tmp = []
    for serviceId in current_user_list.servicesList:
        tmp.append(serviceId)
    print(tmp)
    print("list after appending")

    tmp.remove(int(id))
    print(tmp)
    current_user_list.servicesList = tmp
    print(current_user_list.servicesList)
    db.session.commit()

    # print("the response hia:")
    # print(response.servicesList)
    # faCture = list()
    # print("the response hia:")
    # print(response)
    # for serviceId in response.servicesList:
    #     print(serviceId)
    #     faCture.append(Services.query.get(serviceId))
    # print(faCture)
    # return render_template('viewservices.html', services=faCture)
    # for r in response:
    #     print("l item d response houa")
    #     print(r)
    #     print(r.description)
    #     row = list()
    #     for x in range(len(r)):
    #         row.append(r[x])
    #     services.append(row)
    return redirect('/viewfacture/'+str(current_user.id))


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

