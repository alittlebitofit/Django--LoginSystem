from django.urls import path

from . import views


app_name="signins"

urlpatterns = [
    path("", views.index, name="index"),
	path("register/", views.register, name="register"),
	path("login/", views.login, name="login"),
	path("attemptSignIn/", views.attemptSignIn, name="attemptSignIn"),
	path("success/", views.success, name="success"),
	path("failed/", views.failed, name="failed"),
]
