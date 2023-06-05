from django.http import HttpResponseRedirect
from django.urls import reverse

from django.contrib.auth.models import User

from django.shortcuts import render, redirect

from django.http import HttpResponse

from django.contrib.auth import authenticate, login


def index(request):
	return render(request, "signins/register.html")


def register(request):

	uname = request.POST['username']
	pword = request.POST['password']

	try:
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

		# Always return an HttpResponseRedirect after successfully dealing
		# with POST data. This prevents data from being posted twice if
		# user hits the back button.
		#return HttpResponseRedirect("/signins/login/")
		#return render(request, "signins/login.html")
		return redirect("/signins/signin/")

def signin(request):
	#return render(request, "signins/login.html")

	if request.method == "GET":
		return render(request, "signins/login.html")



#def attemptSignIn(request):

	print("==============attemptSignIn==========")

	uname = request.POST["username"]
	pword = request.POST["password"]

	user = authenticate(request, username=uname, password=pword)

	if user is not None:
		print("Authenticated user")
		login(request, user)
		return redirect("/signins/success")
	else:
		print("Non-authenticated user")
		return redirect("/signins/failed")

	return HttpResponse("<h1 style='font-size:60px'>success or failure?</h1>")




def success(request):
	return HttpResponse("<h1 style='font-size:60px'>CONGRATS FOR SIGNING UP SUCCESSFULLY!</h1>")

def failed(request):
	return HttpResponse("<h1 style='font-size:60px'>To signup page again, but with an error message, and don't for resubmission on back button, that's achieved by redirection</h1>")
