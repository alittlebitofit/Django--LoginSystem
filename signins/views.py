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

import uuid

from .models import TwoFA, BackupCode

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

		user_username = request.user.username
		user_email = request.user.email

		key = b''
		backup_codes_list = []

		if not request.session.exists('2fa_key'):
			key = gen_token(user_username)
			request.session['2fa_key'] = key.decode('utf-8')

			generated_saved_token = base64.b32encode(key).decode('utf-8')
			request.session['generated_saved_token'] = generated_saved_token

			gen_qrcode(user_username, user_email, key)

			gen_totp(key)

			backup_codes_list = gen_backup_codes()
			request.session['backup_codes_list'] = backup_codes_list


		return render(
			request,
			"signins/2fa.html",
			{
				'username': user_username,
				'token': generated_saved_token,
				'backup_codes': backup_codes_list,
			},
		)


	if request.method == 'POST':


		# if the 2fa process is cancelled
		if 'cancel_2fa' in request.POST:
			user_username = request.user.username
			path_to_img = 'signins/static/signins/tmp/'+user_username
			if os.path.exists(path_to_img):
				shutil.rmtree(path_to_img)

			del request.session['2fa_key']
			del request.session['generated_saved_token']
			del request.session['backup_codes_list']

			return redirect('/signins/success')





		# if the user proceeds to verify with totp
		if 'verify_2fa' in request.POST:

			user_username = request.user.username

			user_totp = request.POST['totp']
			generated_token = request.session['generated_saved_token']
			backup_codes_list = request.session['backup_codes_list']

			if len(user_totp) == 6:
				try:
					user_totp = int(user_totp)

				except:
					print("========== exception ocurred ==========")
					return render(
						request,
						'signins/2fa.html',
						{
							'error_message': 'Invalid TOTP',
							'username': user_username,
							'token': generated_token,
							'backup_codes': backup_codes_list,
						},
    	            )

				else:
					key = request.session['2fa_key']
					key = bytes(key, 'utf-8')

					totp = gen_totp(key)

					if int(totp) == user_totp:
						print("========== totp matched ==========")

						token_to_save = TwoFA(user=request.user, token=generated_token)
						token_to_save.save()

						for code in backup_codes_list:
							backup_code = BackupCode(twofa=token_to_save, code=code)
							backup_code.save()

						path_to_img = 'signins/static/signins/tmp/'+user_username
						if os.path.exists(path_to_img):
							shutil.rmtree(path_to_img)

						del request.session['2fa_key']
						del request.session['generated_saved_token']
						del request.session['backup_codes_list']

						logout(request)

						return redirect('/signins')

					else:
						print("========== totp doesnt match ==========")
						return render(
                 		   request,
	                 	   'signins/2fa.html',
	                    	{
		                        'error_message': 'Invalid TOTP',
								'username': user_username,
								'token': generated_token,
								'backup_codes': backup_codes_list,
							},
	    	            )


			else:
				print("========== totp length should be 6 ==========")
				return render(
					request,
					'signins/2fa.html',
					{
						'error_message': 'Invalid TOTP',
						'username': user_username,
						'token': generated_token,
						'backup_codes': backup_codes_list,
					},
				)



	return redirect('/signins/sucess')





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

	return key


def gen_qrcode(user_username, user_email, key):

	""" Step 3: Generating QR Code """

	# Create a temporary directory to store qrcode.
	path_to_img = 'signins/static/signins/tmp/'+user_username

	if not os.path.exists(path_to_img):
		os.makedirs(path_to_img)

	# Generating QR Code
	image_path = path_to_img+'/token_qr.png'

	token = base64.b32encode(key)

	qr_string = 'otpauth://totp/Login-System:' + user_email + '?secret=' + token.decode('utf-8') + '&issuer=Login-System&algorithm=SHA1&digits=6&period=30'

	img = qrcode.make(qr_string)
	img.save(image_path)

	#DELETE TMP FOLDER AFTER 2FA IS ENABLED OR EVEN IF 2FA IS CANCELLED
	#os.rmdir('signins/tmp/q¹'+user_username)
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

	return totp


def gen_backup_codes():
	backup_codes_list = []

	for i in range(10):
		backup_codes_list.append(uuid.uuid4().hex[:10].upper())

	print(backup_codes_list)

	return backup_codes_list
