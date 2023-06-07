from django.db import models

from django.contrib.auth.models import User

# Create your models here.

class TwoFA(models.Model):
	user = models.OneToOneField(
		User,
		on_delete=models.CASCADE,
		primary_key=True,
	)

	token = models.CharField(max_length=32)

	def __str__(self):
		return self.token


class BackupCode(models.Model):
	twofa = models.ForeignKey(TwoFA, on_delete=models.CASCADE)
	code = models.CharField(max_length=10)

	def __str__(self):
		return self.code
