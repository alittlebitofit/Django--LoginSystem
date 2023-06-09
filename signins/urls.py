from django.urls import path

from . import views


app_name="signins"

urlpatterns = [
    path("", views.index, name="index"),
	path("register/", views.register, name="register"),
	path("signin/", views.signin, name="signin"),
	path("success/", views.success, name="success"),
	path("changePassword/", views.changePassword, name="changePassword"),
	path("set2fa/", views.set2fa, name="set2fa"),
	path('verify/', views.verify_2fa, name='verify2fa'),
	path('page_two/', views.page_two),
	path('page_three/', views.page_three),
]
