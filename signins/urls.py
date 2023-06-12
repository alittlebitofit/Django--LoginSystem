from django.urls import path

from . import views


app_name="signins"

urlpatterns = [
    path("", views.IndexView.as_view(), name="index"),
	path("register/", views.RegisterView.as_view(), name="register"),
	path("signin/", views.SigninView.as_view(), name="signin"),
	path("success/", views.SuccessView.as_view(), name="success"),
	path("change-password/", views.ChangePasswordView.as_view(), name="change-password"),
	path("set-2fa/", views.Set_2fa_View.as_view(), name="set-2fa"),
	path('verify/', views.Verify_2fa_View.as_view(), name='verify-2fa'),
	path('disable-2fa/', views.Disable_2fa_View.as_view(), name='disable-2fa'),
]
