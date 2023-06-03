"""
URL configuration for loginSystem project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from django.http import HttpResponse

def welcome(request):
	br = '<br/>'
	h1 = '<h1 style="font-size:48px;">Welcome</h1>'
	res = h1 + br
	signinsRoot = '<a href="signins/" style="font-size:48px;">Signins</a>'
	res = res + signinsRoot + br

	return HttpResponse(res)


urlpatterns = [
	path('signins/', include('signins.urls')),
    path('admin/', admin.site.urls),
	path('', welcome),
]
