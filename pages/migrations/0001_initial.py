# Generated by Django 3.1.2 on 2021-02-04 14:06

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('django_mailbox', '0008_auto_20190219_1553'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Mail',
            fields=[
                ('message_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='django_mailbox.message')),
                ('spam', models.BooleanField(default=False)),
                ('snippet', models.CharField(max_length=100)),
            ],
            bases=('django_mailbox.message',),
        ),
        migrations.CreateModel(
            name='MailBox',
            fields=[
                ('mailbox_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='django_mailbox.mailbox')),
                ('spam_counter', models.IntegerField(default=0)),
                ('received_counter', models.IntegerField(default=0)),
                ('history_id', models.BigIntegerField(default=0)),
                ('bayess_filter_sensibility', models.CharField(choices=[('low', 'low'), ('medium', 'medium'), ('high', 'high')], default='medium', max_length=7)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            bases=('django_mailbox.mailbox',),
        ),
        migrations.CreateModel(
            name='Blacklist',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=30)),
                ('mailbox', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='pages.mailbox')),
            ],
        ),
    ]