from django.http import HttpResponseRedirect
from django.urls import reverse

from django.contrib.auth.models import User

from django.shortcuts import render

from django.http import HttpResponse


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
		return HttpResponseRedirect("/signins/login/")







def login(request):
	return render(request, "signins/login.html")


def attemptSignIn(request):

	print("==============attemptSignIn==========")

	return HttpResponse("success or failure?")




def success(request):
	return render(request, "CONGRATS FOR SIGNING UP SUCCESSFULLY!")

def failed(request):
	return redirect("To signup page again, but with an error message, and don't for resubmission on back button, that's achieved by redirection")
