from django.contrib.auth.models import User

from django.shortcuts import render

from django.http import HttpResponse


def index(request):
	print("whats up")
	return render(request, "signins/register.html")


def register(request):
	uname = request.POST['username']
	pword = request.POST['password']

	try:
		user = User.objects.create_user(uname, password=pword)

	except:

		print("===================================== heyo ========================")

		return HttpResponse("BOO FOR FAILURE")

		#return render(request, "BOO FOR FAILURE")

        # Redisplay the question voting form.
		"""
        return render(
            request,
            "signins/resgister.html",
            {
                "error_message": "You didn't select a choice.",
            },
        )
		"""

	else:

		# Always return an HttpResponseRedirect after successfully dealing
		# with POST data. This prevents data from being posted twice if
		# user hits the back button.
		#return render(request, "CONGRATS FOR SIGNUP SUCCESS!")
		return HttpResponse("CONGRATS FOR SIGNUP SUCCESS!")


def success(request):
	return render(request, "CONGRATS FOR SIGNING UP SUCCESSFULLY!")

def failed(request):
	return redirect("To signup page again, but with an error message, and don't for resubmission on back button, that's achieved by redirection")
	
