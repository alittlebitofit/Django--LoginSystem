from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from django.contrib.auth.models import User

from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login, logout

from django.contrib.auth.decorators import login_required


def index(request):
	"""
		Redirects to logged in page if the user is logged in.
		Otherwise, takes you to registration page
	"""
	if request.user.is_authenticated:
		return redirect("/signins/success")

	return redirect("/signins/register")



def register(request):
	"""Displays signup form as well as handles the registration mechanism"""
	if request.method == "GET":
		return render(request, "signins/register.html")

	uname = request.POST['username']
	pword = request.POST['password']

	try:
		# Try creating a new user
		user = User.objects.create_user(uname, password=pword)

	except:

        # Redisplay the registration because registration failed.
		return render(
			request,
			"signins/register.html",
			{
				"error_message": "Registration failed. Try again.",
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
		return render(request, "signins/signin.html")


	uname = request.POST["username"]
	pword = request.POST["password"]

	user = authenticate(request, username=uname, password=pword)

	if user is not None:
		# Since the user is authenticated, login and then redirect to success page.
		login(request, user)
		return redirect("/signins/success")
	else:

		# Authentication failed. Redisplay the login form.
		return render(
			request,
			"signins/signin.html",
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
		return redirect("/signins/signin")

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
		return redirect("/signins/signin")


# Changes Password.
def changePassword(request):

	# If the user is not authentic, then redirect to signin page.
	if not request.user.is_authenticated:
		return redirect("/signins/signin")

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
			return redirect("/signins/signin")
