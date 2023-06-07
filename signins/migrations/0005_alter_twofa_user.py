# Generated by Django 4.2.1 on 2023-06-07 13:45

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('signins', '0004_alter_twofa_options_alter_twofa_managers_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='twofa',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL),
        ),
    ]
