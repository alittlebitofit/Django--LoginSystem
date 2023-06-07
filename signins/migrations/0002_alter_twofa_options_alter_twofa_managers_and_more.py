# Generated by Django 4.2.1 on 2023-06-07 13:22

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('signins', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='twofa',
            options={},
        ),
        migrations.AlterModelManagers(
            name='twofa',
            managers=[
            ],
        ),
        migrations.RemoveField(
            model_name='twofa',
            name='user_ptr',
        ),
        migrations.AddField(
            model_name='twofa',
            name='user',
            field=models.OneToOneField(default='', on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL),
        ),
    ]
