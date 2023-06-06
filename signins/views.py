from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from django.contrib.auth.models import User

from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login, logout

from django.contrib.auth.decorators import login_required


def index(request):
	"""Simply redirects to registration page"""
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



@login_required
def success(request):
	"""
		Displays a success page on GET request with a LogOut button for now.
		On POST request however, it simply logs the user out.
	"""

	if request.method == "GET":
		return render(request, "signins/success.html")

	logout(request)

	return HttpResponseRedirect("/signins/signin")



def failed(request):
	return HttpResponse("<h1 style='font-size:60px'>To signup page again, but with an error message, and don't for resubmission on back button, that's achieved by redirection</h1>")
