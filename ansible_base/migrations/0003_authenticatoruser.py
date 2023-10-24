# Generated by Django 4.2.5 on 2023-10-11 14:16

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import social_django.storage


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('ansible_base', '0002_authenticator_order'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuthenticatorUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uid', models.CharField(db_index=True, max_length=255)),
                ('extra_data', models.JSONField(default=dict)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('provider', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='authenticator_user', to='ansible_base.authenticator')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='authenticator_user', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'unique_together': {('provider', 'uid')},
            },
            bases=(models.Model, social_django.storage.DjangoUserMixin),
        ),
    ]
