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

from django.views import View

from .utils import tokenRelated


# Landing view of this signins app.
class IndexView(View):
	'''
		Redirects to success page if the user is signed in.
		Otherwise, takes you to registration page.
	'''

	def get(self, request):
		if request.user.is_authenticated:
			return redirect('/signins/success')


		# Implemented these 2 checks so that the url doesn't say 'signin' or 'registration' on failure.

		if 'login_failed' in request.session:
			del request.session['login_failed']

			# Authentication failed. Redisplay the login form with failure message.
			return render(
				request,
				#'signins/sign_backup.html',
				'signins/sign.html',
				{
					'login_failed_message': 'Login failed. Try again.',
				},
			)

		if 'registration_failed' in request.session:
			del request.session['registration_failed']

			# Registration failed. Redisplay the registration form with failure message.
			return render(
				request,
				#'signins/sign_backup.html',
				'signins/sign.html',
				{
					'registration_failed_message': 'Registration failed. Try again.',
					'registration_tab': True,
				}
			)

		if 'registration_tab' in request.session:
			del request.session['registration_tab']

			return render(
                request,
				#'signins/sign_backup.html',
				'signins/sign.html',
                {
                    'registration_tab': True,
                }
            )


		if 'registration_success' in request.session:
			del request.session['registration_success']

			return render(
                request,
                #'signins/sign_backup.html',
                'signins/sign.html',
                {
                    'registration_success_message': 'Successfully signed up! You can now login.',
                }
            )



		#return render(request, 'signins/sign_backup.html')
		return render(request, 'signins/sign.html')



# Helps in registering the user.
class RegisterView(View):
	'''Displays signup form as well as handles the registration mechanism'''

	def get(self, request):
		# If the user is already authenticated then redirect to success page.
		# This situation occurs if the user manually types in the url.
		if request.user.is_authenticated:
			return redirect('/signins/success')

		request.session['registration_tab'] = True

		return redirect('/signins')



	def post(self, request):

		fname = request.POST.get('first_name_register')
		lname = request.POST.get('last_name_register')
		uname = request.POST.get('username_register')
		email = request.POST.get('email_register')
		pword = request.POST.get('password_register')
		pword_repeat = request.POST.get('repeat_password_register')


		tnc_checkbox_register = request.POST.get('tnc_checkbox_register')

		try:
			# Try creating a new user.
			user = User.objects.create_user(
				first_name = fname,
				last_name = lname,
				username = uname,
				email = email,
				password = pword,
			)

		except:
			request.session['registration_failed'] = True
			return redirect('/signins')

	        # Redisplay the registration form because registration failed.
			return render(
				request,
				'signins/sign.html',
				{
					'registration_failed_message': 'Registration failed. Try again.',
					'registration_tab': True,
				},
			)

		else:
			# Successfully created a new user and it was automatically saved in the db.
			request.session['registration_success'] = True

			# Always return an HttpResponseRedirect after successfully dealing
			# with POST data. This prevents data from being posted twice if
			# user hits the back button.
			return redirect('/signins')





# Helps with signing the user in.
class SigninView(View):
	'''Displays signin form as well as handles the signin mechanism'''


	# Load the signin page.
	def get(self, request):
		# If the user is already authenticated then redirect to success page.
		# This situation occurs if the user manually types in the url.
		if request.user.is_authenticated:
			return redirect('/signins/success')

		return redirect('/signins')


	def post(self, request):

		uname = request.POST.get('username_login')
		pword = request.POST.get('password_login')

		remember_me_checkbox_login = request.POST.get('remember_me_checkbox_login')

		# Authenticate the user, don't login yet
		# because we still not to check whether the user has 2fa enabled.
		user = authenticate(request, username=uname, password=pword)

		if user is not None:
			# Since the user is authenticated, login and then redirect to success page
			# only if she has not enabled 2fa.
			# Otherwise, redirect to 2nd page in login process.
			if hasattr(user, 'twofa'):

				# Store the session variables to retrieve the username and password
				# in the 2nd step of the login process.
				# That's because we have not yet logged the user in, so we do not have
				# access to username and password in the next view.

				request.session['authenticate_uname'] = uname
				request.session['authenticate_pword'] = pword

				return redirect('/signins/verify')

			else:
				# Log the user in and then directly go to success page
				# since the user has not enabled 2fa.
				login(request, user)
				return redirect('/signins/success')

		else:

			request.session['login_failed'] = True
			return redirect('/signins')

			# Authentication failed. Redisplay the login form.
			return render(
				request,
				'signins/sign.html',
				{
					'login_failed_message': 'Login failed. Try again.',
				},
			)




# Helps with 2nd factor authentication
class Verify_2fa_View(View):
	'''Displqy the verification page in the 2nd step of the login process.'''


	def get(self, request):

		# Do this instead of checking whether the user is authenticated because
		# user is AnonymousUser at this point, meaning, she is obviously not authenticated.
		# Doing this prevents the user from accessing this page by manually typing the url.
		#
		# This session variable would only exist if the user was redirected here
		# from 1st step of the login process rather than manually typing the url.
		if not 'authenticate_uname' in request.session:
			return redirect('/signins')

		# If all good, then render the 2fa verification page.
		return render(request, 'signins/verify_2fa.html')





	def post(self, request):

		if 'cancel_verifying_2fa' in request.POST:
			# Logout so that the session is cleared.
			logout(request)
			return redirect('/signins')

		elif 'verify_2fa' in request.POST:

			uname = request.session.get('authenticate_uname')
			pword = request.session.get('authenticate_pword')

			# The user would surely be authenticated at this point because this page is accessible only
			# if the user was already authenticated.
			#
			# The reason fot re-authentication is that the user is still AnonymousUser
			# who is not logged in by us yet.
			user = authenticate(request, username=uname, password=pword)


			# If the user chooses to login via TOTP.
			if 'user_input_totp' in request.POST:
				totp_user = request.POST.get('user_input_totp')

				key = bytes(user.twofa.token, 'utf-8')
				#totp = tokenRelated.gen_totp(key) # this is the TOTP we need to compare with
				totp = gen_totp(key) # this is the TOTP we need to compare with


				if totp_user == totp:
					login(request, user)

					# Clear the session variables as we have no further need.
					del request.session['authenticate_uname']
					del request.session['authenticate_pword']

					return redirect('/signins/success')

				else:
					return render(
						request,
						'signins/verify_2fa.html',
						{
							'incorrect_totp_message': 'Invalid TOTP. Please try again.',
						},
					)


			# If the user chooses to login via Backup Code.
			elif 'user_input_backup_code' in request.POST:
				if user.twofa.verify_using_backup_code(request.POST.get('user_input_backup_code')):

					# This block is entered only when the backup code is valid.
					# So simply log the user in, clear the session and redirect
					# to the success page.

					login(request, user)

					del request.session['authenticate_uname']
					del request.session['authenticate_pword']

					return redirect('/signins/success')


				else:

					# Invalid backup code by user.
					return render(
						request,
						'signins/verify_2fa.html',
						{
							'incorrect_backupcode_message': 'Invalid Backup Code. Please try again.',
							'enter_backup_code': True,
						},
					)


# Helps with displaying the success page.
class SuccessView(View):
	'''
		Displays a success page with a Change Password, Delete Account
		and Logout button, only to the logged in user.
		Otherwise, it redirects to Signin page.

		Checks whether the user is logged in first.
		Then proceeds to either change the password, delete the account
			or logout depending upon what the user wants.

		Finally, redirects to Signin page.
	'''

	# GET request always renders a page, a success page in this case.
	def get(self, request):
		# If the user is not authenticated, meaning
		# the user might have manually typed the url without logging in,
		# then redirect to signin page.
		if not request.user.is_authenticated:
			return redirect('/signins')


		# This conditions allows us to display "Disable 2FA"
		# instead of "Enable 2FA" because the user has already enabled it.
		if hasattr(request.user, 'twofa'):
			return render(
				request,
				'signins/success.html',
				{
					'2fa_exists': True,
				},
			)

		return render(request, 'signins/success.html')


	# POST request handling
	def post(self, request):

		if 'change_password_button' in request.POST:
			return redirect('/signins/change-password')

		elif 'delete_account_button' in request.POST:
			request.user.delete()
			logout(request)
			request.session['registration_tab'] = True
			return redirect('/signins')

		elif 'logout_button' in request.POST:
			logout(request)
			return redirect('/signins')

		elif 'enable_2fa_button' in request.POST:
			return redirect('/signins/set-2fa')

		elif 'disable_2fa_button' in request.POST:
			return redirect('/signins/disable-2fa')


		elif 'change_2fa_button' in request.POST:
			return redirect('/signins/set-2fa')




# Helps with disabling 2fa
class Disable_2fa_View(View):

	def get(self, request):
		if not request.user.is_authenticated:
			return redirect('/signins')

		return render(request, 'signins/disable_2fa.html')


	def post(self, request):

		if 'cancel_disabling_2fa' in request.POST:
			return redirect('/signins/success')

		if 'confirm_disabling_2fa' in request.POST:
			#if correct, then d
				#request.user.twofa.delete()
				#return redirect('/signins')

			# if incorrect, then display error

			# If the user chooses to login via TOTP.
			if 'user_input_totp' in request.POST:
				totp_user = request.POST.get('user_input_totp')

				key = bytes(request.user.twofa.token, 'utf-8')
				#totp = tokenRelated.gen_totp(key) # this is the TOTP we need to compare with
				totp = gen_totp(key) # this is the TOTP we need to compare with


				if totp_user == totp:
					request.user.twofa.delete()
					return redirect('/signins/success')

				else:
					return render(
						request,
						'signins/disable_2fa.html',
						{
							'incorrect_totp_message': 'Invalid TOTP. Please try again.',
						},
					)


			# If the user chooses to login via Backup Code.
			elif 'user_input_backup_code' in request.POST:
				if request.user.twofa.verify_using_backup_code(request.POST.get('user_input_backup_code')):

					# This block is entered only when the backup code is valid.
					# So simply delete the 2fa and redirect to the success page.

					request.user.twofa.delete()
					return redirect('/signins/success')


				else:

					# Invalid backup code by user.
					return render(
						request,
						'signins/disable_2fa.html',
						{
							'incorrect_backupcode_message': 'Invalid Backup Code. Please try again.',
							'enter_backup_code': True,
						},
					)




# Changes Password.
class ChangePasswordView(View):

	def get(self, request):
		# If the user is not authenticated, then redirect to signin page.
		if not request.user.is_authenticated:
			return redirect('/signins')

		return render(request, 'signins/change_password.html')



	def post(self, request):
		if 'cancel_new_password_button' in request.POST:
			return redirect('/signins/success')

		elif 'change_password_button' in request.POST:

			password1 = request.POST.get('new_password')
			password2 = request.POST.get('repeat_new_password')

			# If password is empty, display error.
			if password1 == '' or password2 == '':
				return render(
					request,
					'signins/change_password.html',
					{
						'empty_password_error_message': 'Password cannot be empty.',
					},
				)

			# Else change the password and manually save it in db.
			# Although at this point there's no constraint on password.
			else:

				if password1 != password2:
					return render(
						request,
						'signins/change_password.html',
						{
							'passwords_dont_match_message': 'Passwords do not match. Please try again.',
						},
					)

				request.user.set_password(password1)
				request.user.save()
				logout(request)
				return redirect('/signins')




# Sets a new 2fa token and backup codes.
class Set_2fa_View(View):
	'''
		Whether the user wants to enable or change the 2fa token,
		this single function is suffice for both.
	'''

	def get(self, request):
		# This prevents the unauthorized users from accessing this page
		# by manually typing the url.
		if not request.user.is_authenticated:
			return redirect('/signins')


		user_username = request.user.username
		user_email = request.user.email

		# It won't be empty if the user refreshes the page.
		generated_saved_token = request.session.get('generated_saved_token')

		# Use already generated backup codes if the user refreshes the page.
		backup_codes_list = request.session.get('backup_codes_list')

		# This preventw generation of new token on page refresh.
		if not '2fa_key' in request.session:
			#key = tokenRelated.gen_token(user_username)
			key = gen_token(user_username)
			request.session['2fa_key'] = key.decode('utf-8')

			generated_saved_token = base64.b32encode(key).decode('utf-8')
			request.session['generated_saved_token'] = generated_saved_token

			#tokenRelated.gen_qrcode(user_username, user_email, key)
			gen_qrcode(user_username, user_email, key)

			#tokenRelated.gen_totp(key)
			gen_totp(key)

			#backup_codes_list = tokenRelated.gen_backup_codes()
			backup_codes_list = gen_backup_codes()
			#request.session['backup_codes_list'] = tokenRelated.backup_codes_list
			request.session['backup_codes_list'] = backup_codes_list

		# Render the page with the token and backup codes.
		return render(
			request,
			'signins/set_2fa.html',
			{
				'username': user_username, # This is used by static image loading template
				'token': generated_saved_token,
				'backup_codes': backup_codes_list,
			},
		)





	def post(self, request):
		# if the 2fa process is cancelled
		if 'cancel_2fa_button' in request.POST:

			# Delete the qr code if not already deleted.
			# This qr code was temporary.
			path_to_img = 'signins/static/signins/tmp/'+request.user.username
			if os.path.exists(path_to_img):
				shutil.rmtree(path_to_img)

			# Clear the session.
			del request.session['2fa_key']
			del request.session['generated_saved_token']
			del request.session['backup_codes_list']

			# Go back to the success page.
			return redirect('/signins/success')





		# if the user proceeds to confirm 2fa with totp
		if 'verify_2fa_button' in request.POST:

			user_username = request.user.username

			user_totp = request.POST.get('user_input_totp')
			generated_token = request.session.get('generated_saved_token')
			backup_codes_list = request.session.get('backup_codes_list')

			key = request.session.get('2fa_key')
			key = bytes(key, 'utf-8')

			#totp = tokenRelated.gen_totp(key)
			totp = gen_totp(key)

			# If the TOTP is correct.
			if totp == user_totp:

				# Delete old token first if it exists
				# otherwise old backup codes won't be deleted.
				if hasattr(request.user, 'twofa'):
					request.user.twofa.delete()

				# Save the new token in db.
				token_to_save = TwoFA(user=request.user, token=generated_token)
				token_to_save.save()

				# Save the new backuo codes in db.
				for code in backup_codes_list:
					backup_code = BackupCode(twofa=token_to_save, code=code)
					backup_code.save()


				# Delete this temporary qr code if it exists.
				path_to_img = 'signins/static/signins/tmp/'+user_username
				if os.path.exists(path_to_img):
					shutil.rmtree(path_to_img)

				# Logout, it automatically clears out the session.
				logout(request)

				# Redirect to login page.
				return redirect('/signins')


			# If the TOTP is incorrect.
			else:

				return render(
					request,
					'signins/set_2fa.html',
					{
						'invalid_totp_message': 'Invalid TOTP',
						'username': user_username,
						'token': generated_token,
						'backup_codes': backup_codes_list,
					},
				)




# Helper function - generates a 32-character 2FA token.
def gen_token(user_username):
	'''Step 1: Generating a base32-encoded token'''

	random_number = random.randint(1000000000, 9999999999)
	current_time = int(time.time())

	string = user_username + str(random_number) + str(current_time)

	l = list(string)

	k = ''

	for i in range(20):
		k += str(l.pop(random.randrange(len(l))))

	key = bytes(k, 'utf-8')

	return key




# Helper function - generates a QR code.
def gen_qrcode(user_username, user_email, key):
	'''Step 2: Generating QR Code'''

	# Create a temporary directory to store qrcode if it doesn't already exist.
	path_to_img = 'signins/static/signins/tmp/'+user_username
	if not os.path.exists(path_to_img):
		os.makedirs(path_to_img)

	# Location to store QR code temporarily.
	image_path = path_to_img+'/token_qr.png'

	# Token.
	token = base64.b32encode(key)

	qr_string = 'otpauth://totp/Login-System:' + user_email + '?secret=' + token.decode('utf-8') + '&issuer=Login-System&algorithm=SHA1&digits=6&period=30'

	# This statement generates QR code.
	img = qrcode.make(qr_string)

	# This statement saves the QR code in a temporary location.
	img.save(image_path)





# Helper function - generates TOTP
def gen_totp(key):
	'''Step 3: Generating hmac hexdigest and TOTP'''

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





# Helper function - generates backup codes.
def gen_backup_codes():
	backup_codes_list = []

	for i in range(10):
		backup_codes_list.append(uuid.uuid4().hex[:10].upper())

	return backup_codes_list
