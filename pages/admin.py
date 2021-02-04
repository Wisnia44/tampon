from django.contrib import admin
from .models import Mail, MailBox

# Register your models here.
admin.site.register(Mail)
admin.site.register(MailBox)