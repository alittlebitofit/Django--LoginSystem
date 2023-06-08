from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from django.contrib.auth.models import User

from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login, logout

import hashlib
import hmac
import math
import time

import base64
import qrcode

import random
import os

import shutil

def index(request):
	"""
		Redirects to logged in page if the user is logged in.
		Otherwise, takes you to registration page
	"""
	if request.user.is_authenticated:
		return redirect("/signins/success")

	#return redirect("/signins/register")
	return render(request, "signins/sign.html")



def register(request):
	"""Displays signup form as well as handles the registration mechanism"""
	if request.method == "GET":
		return render(
			request,
			"signins/sign.html",
			{
				"registration_tab": True,
			},
		)

	#uname = request.POST['username']
	#pword = request.POST['password']

	fname = request.POST['first_name_register']
	lname = request.POST['last_name_register']
	uname = request.POST['username_register']
	email = request.POST['email_register']
	pword = request.POST['password_register']
	pword_repeat = request.POST['repeat_password_register']

	tnc_checkbox_register = request.POST['tnc_checkbox_register']

	try:
		# Try creating a new user
		user = User.objects.create_user(
			first_name = fname,
			last_name = lname,
			username = uname,
			email = email,
			password = pword,
		)

	except:

        # Redisplay the registration because registration failed.
		return render(
			request,
			"signins/sign.html",
			{
				"error_message": "Registration failed. Try again.",
				"registration_tab": True,
			},
		)

	else:

		# Successfully created a new user and it was automatically saved in the db.

		# Always return an HttpResponseRedirect after successfully dealing
		# with POST data. This prevents data from being posted twice if
		# user hits the back button.
		return redirect("/signins/signin/")


def signin(request):
	"""Displays signin form as well as handles the signin mechanism"""

	if request.method == "GET":
		return render(request, "signins/sign.html")


	uname = request.POST["username_login"]
	pword = request.POST["password_login"]

	remember_me_checkbox_login = request.POST['remember_me_checkbox_login']

	user = authenticate(request, username=uname, password=pword)

	if user is not None:
		# Since the user is authenticated, login and then redirect to success page.
		login(request, user)
		return redirect("/signins/success")
	else:

		# Authentication failed. Redisplay the login form.
		return render(
			request,
			"signins/sign.html",
			{
				"error_message": "Login failed. Try again.",
			},
		)



def success(request):
	"""
		Displays a success page with a Change Password, Delete Account
		and Logout button, only to the logged in user.
		Otherwise, it redirects to signin page.

		Checks whether the user is logged in first.
		Then proceeds to either change the password, delete the account
			or logout depending upon what the user wants.
		Finally, redirects to Signin page.
	"""

	# If the user is not authentic, then redirect to signin page.
	if not request.user.is_authenticated:
		return redirect("/signins")

	# GET request always renders a page, a success page in this case.
	if request.method == "GET":
		return render(request, "signins/success.html")


	# POST request handling
	if "changePassword" in request.POST:
		return redirect("/signins/changePassword")

	elif "deleteAccount" in request.POST:
		request.user.delete()
		return redirect("/signins/register")

	elif "logoutUser" in request.POST:
		logout(request)
		return redirect("/signins")

	elif "2fa" in request.POST:
		return redirect("/signins/2fa")


# Changes Password.
def changePassword(request):

	# If the user is not authentic, then redirect to signin page.
	if not request.user.is_authenticated:
		return redirect("/signins")

	# A GET request, so render an appropriate page.
	if request.method == "GET":
		return render(request, "signins/changePassword.html")

	# POST request handling
	if "cancel" in request.POST:
		return redirect("/signins/success")

	elif "change" in request.POST:
		# If password is empty, display error.
		if request.POST["new_password"] == "":
			return render(
				request,
				"signins/changePassword.html",
				{
					"empty_password": "Password cannot be empty.",
				},
			)

		# Else change the password and manually save it in db.
		else:
			request.user.set_password(request.POST["new_password"])
			request.user.save()
			logout(request)
			return redirect("/signins")


def twoFa(request):

	if not request.user.is_authenticated:
		return redirect("/signins")



	if request.method == 'GET':
		return render(
			request,
			"signins/2fa.html",
			{
				"gen": True,
			},
		)



	if request.method == 'POST':
		user_username = request.user.username
		shutil.rmtree('signins/tmp/'+user_username)
		pass



	return HttpResponse("hmm")





def gen_token(user_username):

	""" Step 1: Generating a base32-encoded token """

	random_number = random.randint(1000000000, 9999999999)
	current_time = int(time.time())

	string = user_username + str(random_number) + str(current_time)

	l = list(string)

	k = ''

	for i in range(20):
		k += str(l.pop(random.randrange(len(l))))

	key = bytes(k, 'utf-8')

	token = base64.b32encode(key)

	return (key, token)


def gen_qrcode(user_username, user_email, token):

	""" Step 3: Generating QR Code """

	# Create a temporary directory to store qrcode.
	os.makedirs('signins/templates/signins/tmp/'+user_username)

	# Generating QR Code
	image_path = 'signins/tmp/'+user_username+'/token_qr.png'

	qr_string = 'otpauth://totp/Login-System:' + user_email + '?secret=' + token.decode('utf-8') + '&issuer=Login-System&algorithm=SHA1&digits=6&period=30'

	img = qrcode.make(qr_string)
	img.save(image_path)

	#DELETE TMP FOLDER AFTER 2FA IS ENABLED OR EVEN IF 2FA IS CANCELLED
	#os.rmdir('signins/tmp/'+user_username)
	#shutil.rmtree('signins/templates/signins/tmp/'+user_username)





def gen_totp(key):

	""" Step 2: Generating hmac hexdigest """

	# length of OTP in digits
	length = 6

	# timestamp or time-window for which the token is valid
	step_in_seconds = 30


	t = math.floor(time.time() // step_in_seconds)

	hmac_object = hmac.new(key, t.to_bytes(length=8, byteorder='big'), hashlib.sha1)
	hmac_sha1 = hmac_object.hexdigest()

	# truncate to 6 digits
	offset = int(hmac_sha1[-1], 16)
	binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
	totp = str(binary)[-length:]
	print(totp)
