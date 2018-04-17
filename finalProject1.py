# -*- coding: utf-8 -*-
from flask import Flask, render_template, url_for
from flask import request, redirect, jsonify, flash, abort, g

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from database_setup import Base, Restaurant, MenuItem, User

# for creating session token
# (in order to verify that the person who is logging is the actual one)
from flask import session as login_session
import random
import string

# for server side in order to respond to client's request
from oauth2client.client import flow_from_clientsecrets
# creates flow object storing client's id,secrets
from oauth2client.client import FlowExchangeError 
# inorder to handle error
import httplib2
import json 
# provide API to convert in memory objects to serailized represenattion
from flask import make_response 
# converts return value to real response object
import requests

from flask_httpauth import HTTPBasicAuth 
auth=HTTPBasicAuth 
# authentication

app=Flask(__name__)

CLIENT_ID=json.loads(open('client_secrets.json','r').read())['web']['client_id']

engine=create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind=engine
DBSession=sessionmaker(bind=engine)
session=DBSession()


def  getUserInfo(user_id):
	user=session.query(User).filter_by(id=user_id).one()
	return user

def getRandomToken():
	api_token=''.join(random.choice(string.ascii_uppercase+string.digits) for x in xrange(32))
	return api_token

#@app.route('/fbconnect', methods=['POST'])
#def fbconnect():
#	if request.args.get('state') != login_session['state']:
#		response = make_response(json.dumps('Invalid state parameter.'), 401)
#		response.headers['Content-Type'] = 'application/json'
#		return response
#	access_token = request.data
#	print ("access token received %s " % access_token)


#	app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
#		'web']['app_id']
#	app_secret = json.loads(
#		open('fb_client_secrets.json', 'r').read())['web']['app_secret']
#	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
#		app_id, app_secret, access_token)
#	h = httplib2.Http()
#	result = h.request(url, 'GET')[1]


	# Use token to get user info from API
#	userinfo_url = "https://graph.facebook.com/v2.8/me"
#	'''
#		Due to the formatting for the result from the server token exchange we have to
#		split the token first on commas and select the first index which gives us the key : value
#		for the server access token then we split it on colons to pull out the actual token value
#		and replace the remaining quotes with nothing so that it can be used directly in the graph
#		api calls
#	'''
#	token = result.split(',')[0].split(':')[1].replace('"', '')

#	url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
#	h = httplib2.Http()
#	result = h.request(url, 'GET')[1]
	# print "url sent for API access:%s"% url
	# print "API JSON result: %s" % result
#	data = json.loads(result)
#	login_session['provider'] = 'facebook'
#	login_session['username'] = data["name"]
#	login_session['email'] = data["email"]
#	login_session['facebook_id'] = data["id"]
	# The token must be stored in the login_session in order to properly logout
#	login_session['access_token'] = token
	# Get user picture
#	url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
#	h = httplib2.Http()
#	result = h.request(url, 'GET')[1]
#	data = json.loads(result)
#	login_session['picture'] = data["data"]["url"]
	# see if user exists
#	user_id = getUserID(login_session['email'])
#	if not user_id:
#		user_id = createUser(login_session)
#	login_session['user_id'] = user_id
#	output = ''
#	output += '<h1>Welcome, '
#	output += login_session['username']
#	output += '!</h1>'
#	output += '<img src="'
#	output += login_session['picture']
#	output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
#	flash("Now logged in as %s" % login_session['username'])
#	return output

#@app.route('/fbdisconnect')
#def fbdisconnect():
#	facebook_id = login_session['facebook_id']
	# The access token must me included to successfully logout
#	access_token = login_session['access_token']
#	url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
#	h = httplib2.Http()
#	result = h.request(url, 'DELETE')[1]
#	return "you have been logged out"

@app.route('/gconnect',methods=['GET','POST'])
def gconnect():
		
		if request.args.get('state') != login_session['state']:
			response = make_response(json.dumps('Invalid State Parameter'), 401)
			response.headers['Content-Type'] = 'application/json'
			return response
		code = request.data
		try:
        # Upgrade the authorization code to credentials object
			oauth_flow = flow_from_clientsecrets('client_secrets.json', scope="")
			oauth_flow.redirect_uri = "postmessage"
        # Exchange the one time code with Google OAuth to get the credentials
        # object.
			credentials = oauth_flow.step2_exchange(code)
		except FlowExchangeError:
			response = make_response(json.dumps(
			'Failed to upgrade the authorization code.', 401))
			response.headers['Content-Type'] = "application/json"
			return response
    # Check that the acess token is valid
		access_token = credentials.access_token
		url = ("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s" %
           access_token)
		h = httplib2.Http()
		resp, content = h.request(url, 'GET')
		result = json.loads(content.decode('utf-8'))

    # If there was an error in access token, abort.
		if 'error' in result:
			response = make_request(json.dumps("Token's user ID doesn't match the given user id"), 401)
			response.headers['Content-Type'] = "application/json"
			return response
    # Verify that the access token is used for the intended user
		gplus_id = credentials.id_token['sub']
		if result['user_id'] != gplus_id:
			response = make_response(json.dumps(
			"Token's user ID doesn't match the user id"), 401)
			response.headers['Content-Type'] = "application/json"
			return response
		if result['issued_to'] != CLIENT_ID:
			response = make_response(json.dumps(
			"Token's client ID doesn't match"), 401)
			print("Token's client ID doesn't match the app's")
			response.headers['Content-Type'] = "application/json"
			return response
    # Check if user is already logged in.
		stored_credentials = login_session.get('access_token')
		stored_gplus_id = login_session.get('gplus_id')
		if stored_credentials is not None and gplus_id == stored_gplus_id:
			response = make_response(json.dumps("User is already logged in"), 200)
			response.headers['Content-Type'] = "application/json"
			return response
    # Store the acess token in the login session for later use
		login_session['access_token'] = credentials.access_token
		login_session['gplus_id'] = gplus_id

    # Get user info
		userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
		params = {'access_token': credentials.access_token, 'alt': 'json'}
		answer = requests.get(userinfo_url, params=params)
		data = json.loads(answer.text)

		login_session['username'] = data["username"]
		login_session['picture'] = data["picture"]
		login_session['email'] = data["email"]

		userInfo = session.query(User).filter_by(email=data["email"]).one()
    # If a new user is logged in, then generate an random api key and add it
    # to the Users table.
		if userInfo is None:
			newUser = User(name=data["username"], email=data["email"],picture=data["picture"],api_key=getRandomToken())
			session.add(newUser)
			session.commit()

		output = ''
		output += '<h1>Welcome, '
		output += login_session['username']
		output += '!</h1>'
		output += '<img src="'
		output += login_session['picture']
		output += ' " style="width:300px;height:300px;'
		output += 'border-radius:150px;-webkit-border-radius:150px;'
		output += '-moz-border-radius:150px;"> '
		return output


# inorder to disconnect user i.e to logout
@app.route('/gdisconnect')
def gdisconnect():
	   # Check if the user is already logged out.
	if 'access_token' not in login_session or login_session['access_token'] is None:
  		return redirect(url_for('showRestaurants'))
	access_token = login_session.get('access_token')
	if access_token is None:
		response = make_response('Currect user not connected.', 401)
		response.headers['Content-Type'] = "application/json"
		return response
    # Revoke the access token given by  Google OAuth.
	url = "https://accounts.google.com/o/oauth2/revoke?token=%s" % access_token
	h = httplib2.Http()
	resp, content = h.request(url, 'GET')
	print(resp.get('status'))
	flash("Logged out!")
	login_session['state'] = None
	login_session['access_token'] = None
	return redirect(url_for('showRestaurants'))

# create a state token to prevent request forgery
@app.route('/login')
def showLogin():
	state=''.join(random.choice(string.ascii_uppercase+string.digits) for x in xrange(32))
	login_session['state']=state
	return render_template('login.html',STATE=state)

@app.route('/restaurants/JSON')
def restaurantJSON():
	restaurants=session.query(Restaurant).all()
	return jsonify(Restaurant=[restaurant.serialize for restaurant in restaurants])

@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
	restaurant=session.query(Restaurant).filter_by(id=restaurant_id).one()
	items=session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
	return jsonify(MenuItem=[i.serialize for i in items])

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id,menu_id):
	item=session.query(MenuItem).filter_by(id=menu_id).one()
	return jsonify(MenuItem=MenuItem.serialize)

@app.route('/')
@app.route('/restaurants/') # show all restaurants
def showRestaurants():
	restaurants=session.query(Restaurant).all()	
	return render_template('publicrestaurants.html', restaurants=restaurants)
	# return "This page will show all restaurants"

@app.route('/restaurants/new/',methods=['GET','POST']) # create new restaurant
def newRestaurant():
	if 'access_token' not in login_session or login_session['access_token'] is None:
		response = make_response(json.dumps('User is not logged in'),401)
		response.headers['Content-type']='application/json'
		return response
	if request.method == 'POST':
		newRestaurantInfo = Restaurant(name=request.form['name'])
		session.add(newRestaurantInfo)
		session.commit()
		flash("New Restaurant created")
		return redirect(url_for('showRestaurants'))
	else:	
		return render_template('newRestaurant.html', new='newRestaurantInfo')
	# return "This page will be making a new restaurant"

@app.route('/restaurants/<int:restaurant_id>/edit',methods=['GET','POST']) #edit rest info
def editRestaurant(restaurant_id):
	if 'access_token' not in login_session or login_session['access_token'] is None:
		return redirect('/login')
	restaurant=session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		if request.name['name']:
			restaurant.name = request.form['name']
		flash("Restaurant successfully editted")
		return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
	else:	
		return render_template('editRestaurant.html', restaurant=restaurant)
	# return "This page will be editing restaurants"

#delete restaurant info
@app.route('/restaurants/<int:restaurant_id>/delete',methods=['GET','POST']) 
def deleteRestaurant(restaurant_id):
	deletedRestaurant=session.query(Restaurant).filter_by(id=restaurant_id).one()
	if 'access_token' not in login_session or login_session['access_token'] is None:
		# return "<script>function myFunc(){ alert('You are  not allowed to delete this data.Please create your own restaurant in order to delete it);}</script><body onload='myFunc()'>"	
		redirect(url_for('showRestaurants'))
	if request.method == 'POST':
		session.delete(deletedRestaurant)
		session.commit()
		flash("Restaurant successfully deleted")
		return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
	else:	
		return render_template('deleteRestaurant.html',restaurant=deletedRestaurant)
	# return "This page will be editing restaurants"

@app.route('/restaurants/<int:restaurant_id>/')
@app.route('/restaurants/<int:restaurant_id>/menu') #show restaurant menu
def showMenu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
	return render_template('publicmenu.html', restaurant=restaurant, items=items)
	# return "This page is menu for restaurants"

#  create new menu
@app.route('/restaurants/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
	if 'access_token' not in login_session or login_session['access_token'] is None:
		return redirect('/login')
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
	if not restaurant:
		flash("This restaurant doesnot exist,so cannot create an item")
		redirect(url_for('showRestaurants'))
	if restaurant.user_id != login_session['user_id']:
		flash("You are not allowed to create")
		redirect(url_for('showMenu', restaurant_id=restaurant_id))	
	if request.method == 'POST':
	 	newItem = MenuItem(name=request.form['name'], desctiption=request.form['description'], price=request.form['price'], restaurant_id=restaurant_id, user_id=restaurant.user_id)
	 	session.add(newItem)
	 	session.commit()
	 	flash("New Menu Item created")
	 	return redirect(url_for('showMenu', restaurant_id=restaurant_id))
	else: 	
		return render_template('newMenuItem.html', restaurant_id=restaurant_id, new=newItem)
		# return "This page will be making a new menu item for restaurants"

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/edit',methods=['GET','POST']) #edit menu item
def editMenuItem(restaurant_id,menu_id):
		if 'access_token' not in login_session or login_session['access-token'] is None:
		   return redirect('/login')
		edittedMenu = session.query(MenuItem).filter_by(id=menu_id).one()
		restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
		creator = getUserInfo(restaurant.user_id)
		if not restaurant:
			flash("No such restaurant exist")
			redirect(url_for('showRestaurants'))
		if not edittedMenu:
			flash("no such menu item exist")
			redirect(url_for('showMenu', restaurant_id=restaurant_id))	
		if creator.id != login_session['user_id']:
			flash("You need to create your own menu,in order to edit it.")	
		if request.method == 'POST':
			if request.form['name']:
				edittedMenu.name = request.form['name']
			if request.form['description']:
				edittedMenu.name = request.form['description']
			if request.form['price']:
				edittedMenu.name = request.form['price']
			session.add(edittedMenu)
			sesison.commit()
			flash("Menu Item successfully editted")
			return redirect(url_for('showMenu', restaurant_id=restaurant_id))
		else:	
			return render_template('editMenuItem.html', restaurant_id=restaurant_id, menu_id=menu_id, i=edittedMenu)
	#  return "This page is for editing menu item"

@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/delete',methods=['GET','POST']) #delete menu item
def deleteMenuItem(restaurant_id,menu_id):
	if 'access_token' not in login_session or login_session['access_token'] is None:
		return redirect('/login')
	restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()	
	deletedItem=session.query(MenuItem).filter_by(id=menu_id).one()
	creator=getUserInfo(restaurant.user_id)
	if not restaurant:
		flash("This restaurant doesnot exist")
		redirect(url_for('showRestaurants'))
	if	not deletedItem:
		flash("This item doesnot exist")
		redirect(url_for('showMenu', restaurant_id=restaurant_id))
	if restaurant.user_id!=login_session['user_id']:
		flash("You are not allowed to delete,as u r not logged in")
		redirect(url_for('showMenu', restaurant_id=restaurant_id))
	if creator.id!=login_session['user_id']:
			flash(" You need to create your own menu,in order to delete it.")		
	if request.method=='POST':
		session.delete(deletedItem)
		session.commit()
		flash("Menu Item successfully deleted")
		return redirect(url_for('showMenu', restaurant_id=restaurant_id))
	else:	
	   return render_template('deleteMenuItem.html', restaurant_id=restaurant_id, i=deletedItem)
	# return "This page is for deleting menu item"


if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.debug = True
	app.run( host = '0.0.0.0', port = 5000 )
