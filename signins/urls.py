from django.urls import path

from . import views


app_name="signins"

urlpatterns = [
    path("", views.index, name="index"),
	path("register/", views.register, name="register"),
	path("success/", views.success, name="success"),
	path("failed/", views.failed, name="failed"),
]
