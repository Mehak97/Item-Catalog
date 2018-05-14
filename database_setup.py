#configuration 
import os,random,string
import sys  #it provides a number of functions and variables
from sqlalchemy import Column,ForeignKey,Integer,String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship,sessionmaker # in order to create foreign key relations
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context # lib fro password hashing
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base=declarative_base()
#secret_key=''.join(random.choice(string.ascii_uppercase+string.digits) for x in xrange(32))

class User(Base):
	__tablename__='user'
	name=Column(String(80))
	id=Column(Integer,primary_key=True)
	picture=Column(String(80))
	email=Column(String(80))
	#password_hash=Column(String(80))
	#username=Column(String(80))
	api_key=Column(String(80),nullable=False)
		# called when a new user is registering or changing password
	#def hash_password(self,password):
	#		self.password_hash=pwd_context.encrypt(password)
	#def verify_password(self,password):
	#		return pwd_context.verify(password,self.password_hash)
	#def generate_auth_token(self,expiration=600):
	#		s=Serializer(secret_key,expire=expiration)
	#		return s.dumps({'id':self.id})
	#@staticmethod  #used bcoz user will only be known once token is decoded
	#def verify_auth_token(self):
	#		s=Serializer(secret_key)
	#		try:
	#			data=s.loads(token)
	#		except SignatureExpired:
            #valid token, but expired
	#			return None
	#		except BadSignature:
            #invalid token
	#			return None
	#		user_id=data['id']
	#		return user_id         

class Restaurant(Base):   # class
		__tablename__='restaurant'    #table
		name=Column(String(80),nullable=False)  # this field is compulsory to be filed
		id=Column(Integer,primary_key=True)
		user_id=Column(Integer,ForeignKey('user.id'))
		user=relationship(User)
		@property
		def serialize(self):
				return{
				'name':self.name,
				'id':self.id
				}
 
class MenuItem(Base):
	__tablename__='menu_item'
	name=Column(String(80)) 
	id=Column(Integer,primary_key=True)
	course=Column(String(250))
	description=Column(String(250))
	price=Column(String(8))
	restaurant_id=Column(Integer,ForeignKey('restaurant.id'))
	restaurant=relationship(Restaurant)
	user_id=Column(Integer,ForeignKey('user.id'))
	user=relationship(User)
	@property
	def serialize(self):
        #returns object data in easily serializibale format
				return {
							'name':self.name,
							'description':self.description,
							'id':self.id,
							'price':self.price,
							'course':self.course,
							}


## at the end of file
engine=create_engine('postgresql://mehak:mehak@localhost/restaurants')
Base.metadata.create_all(engine)  # goes to db & add classes that will be created as new tables in db
