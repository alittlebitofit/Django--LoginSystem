from django.contrib import admin

# Register your models here.

from .models import TwoFA, BackupCode

admin.site.register(TwoFA)
admin.site.register(BackupCode)
