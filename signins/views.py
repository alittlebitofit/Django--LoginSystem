from django.http import HttpResponse


def index(request):
    return HttpResponse("Hello, world. <p>You're</p> at the polls index.")
