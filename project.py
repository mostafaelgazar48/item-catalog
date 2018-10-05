from unicodedata import category

from flask import Flask,request,url_for,render_template,redirect,make_response,jsonify,flash
from sqlalchemy import create_engine
from database_setup import Base,Category,CatalogItem,User
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps


engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBsession = sessionmaker(bind=engine)
session = DBsession()

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "catalogitem"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login')
def showLogin():
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code, now compatible with Python3
    #request.get_data()
    code = request.data.decode('utf-8')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider']='google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data.get("email")

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
        # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response





@app.route('/categories/')
def show_Catalog():
    category = session.query(Category).all()
    items = session.query(CatalogItem).order_by(CatalogItem.id.desc())
    count = items.count()
    if 'username' not in login_session:
       return render_template('catalogs.html', category=category, count=count, items=items)
    else:
        return render_template('public_catalog.html', category=category, count=count, items=items)


@app.route('/categories/new', methods=['POST','GET'])
@login_required

def new_categories():

    if request.method =='POST':
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserID(login_session['email'])
        newcategory = Category(
            name= request.form['name'],
            user_id=login_session['user_id']
        )
        session.add(newcategory)
        session.commit()
        flash("new category committed")
        return redirect(url_for("show_Catalog"))
    return render_template('new_category.html')
@app.route('/category/<int:category_id>/delete/',methods= ['POST','GET'])
@login_required

def delete_Category(category_id):
    deleted = session.query(Category).filter_by(id= category_id).one()
    if deleted.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authori   zed!')}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(deleted)
        session.commit()
        return redirect(url_for('show_Catalog'))
    return render_template('delete_category.html',category=deleted)


@app.route('/category/<int:category_id>/edit', methods=['POST','GET'])
@login_required

def edit_Category(category_id):
    edited = session.query(Category).filter_by(id=category_id).one()
    if edited.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authori   zed!')}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        edited.name =request.form['name']
        return redirect(url_for('show_Catalog'))
    return render_template('edit_category.html',category=edited)


@app.route('/category/<int:category_id>/items')
def categoryItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    categories =session.query(Category).all()
    items = session.query(CatalogItem).filter_by(category_id=category_id).order_by(CatalogItem.id.desc())
    count = items.count()
    return render_template('catalog_menu.html',category=category,categories=categories,items=items,count=count)


@app.route('/categories/<int:category_id>/items/<int:item_id>')
def showCatalogItem(category_id,item_id):
    category= session.query(Category).filter_by(id = category_id).one()
    item= session.query(CatalogItem).filter_by(id = item_id).one()
    return render_template('catalogItem_menu.html',category=category,item=item)


@app.route('/categories/items/new', methods=['POST','GET'])
@login_required

def newCatalogItem():
    all_categories = session.query(Category).all()
    if request.method == 'POST':
        addNewItem = CatalogItem(
            name=request.form['name'],
            description=request.form['desc'],
            price=request.form['price'],
            category_id=request.form['category'],
            user_id=login_session['user_id'])
        session.add(addNewItem)
        session.commit()
        flash("New catalog item created!", 'success')
        return redirect(url_for('show_Catalog'))

    return render_template('new_item.html',categories=all_categories)

@app.route('/categories/<int:category_id>/items/<int:item_id>/edit', methods=['POST','GET'])
@login_required

def ediCatalogItem(category_id,item_id):
    categories=session.query(Category).all()
    edited = session.query(CatalogItem).filter_by(id=item_id).one()
    if edited.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authori   zed!')}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            edited.name=request.form['name']
        if request.form['desc']:
            edited.description=request.form['desc']
        if request.form['price']:
            edited.price=request.form['price']
        if request.form['category']:
            edited.category_id= request.form['category']
        session.add(edited)
        session.commit()

        return redirect(url_for('show_Catalog'))

    return render_template('edit_catalog_item.html',categories=categories,item=edited)

@app.route('/categories/<int:category_id>/items/<int:item_id>/delete', methods=['POST','GET'])
@login_required

def deleteCatalogItem(category_id,item_id):
    deleted= session.query(CatalogItem).filter_by(id=item_id).one()
    if deleted.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authori   zed!')}</script><body onload='myFunction()'>"
    if request.method =='POST':
        session.delete(deleted)
        session.commit()
        return redirect(url_for('show_Catalog'))
    return render_template('delete_catalog_item.html',item=deleted)







# ------------- json libraries---------

@app.route('/api/categories/json')
def jsonCategories():
    categories =session.query(Category).all()
    return jsonify(categories=[x.serialize for x in categories])

@app.route('/api/cataegories/<int:category_id>/item/<int:item_id>/json')
def jsonCatalogItems(category_id,item_id):
    item = session.query(CatalogItem).filter_by(id=item_id).one()
    return jsonify(item =item.serialize)

@app.route('/api/category/items')
def jsoncategoryItems():
    items = session.query(CatalogItem).order_by(CatalogItem.id.desc()).all()
    return jsonify(items= [i.serialize for i in items])

if __name__ == '__main__':
    app.secret_key='super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0',port=5050)
