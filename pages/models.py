from django_mailbox.models import Mailbox, Message
from django.contrib.auth.models import User
from django.db import models
from django.conf import settings
from django.urls import reverse
from rest_framework.reverse import reverse as api_reverse
from picklefield.fields import PickledObjectField


# Create your models here.
class MailBox (Mailbox):
	""" 
	Fields inherited from Mailbox:
		id (AutoField) – Id
		name (CharField) – Name
		uri (CharField) – Example: imap+ssl://myusername:mypassword@someserver 
						Internet transports include ‘imap’ and ‘pop3’;
						common local file transports include ‘maildir’, ‘mbox’, 
						and less commonly ‘babyl’, ‘mh’, and ‘mmdf’. 
						Be sure to urlencode your username and password 
						should they contain illegal characters (like @, :, etc).
		from_email (CharField) – Example: MailBot &lt;mailbot@yourdomain.com&gt;
						’From’ header to set for outgoing email.
						If you do not use this e-mail inbox for outgoing mail, this setting is unnecessary.
						If you send e-mail without setting this, your ‘From’ header 
						will’be set to match the setting DEFAULT_FROM_EMAIL.
		active (BooleanField) – Check this e-mail inbox for new e-mail messages during polling cycles. 
						This checkbox does not have an effect upon whether mail is collected here 
						when this mailbox receives mail from a pipe, 
						and does not affect whether e-mail messages can be dispatched from this mailbox.
		last_polling (DateTimeField) – The time of last successful polling for messages.
						It is blank for new mailboxes and is not set for mailboxes that only receive messages 
						via a pipe.
	"""
	owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
	spam_counter = models.IntegerField(default=0)
	received_counter = models.IntegerField(default=0)
	history_id = models.BigIntegerField(default=0)
	bayess_filter_choices =[
		('low','low'),
		('medium','medium'),
		('high','high')
		]
	bayess_filter_sensibility = models.CharField(
		max_length=7, 
		choices=bayess_filter_choices, 
		default='medium'
		)
	#blacklist = PickledObjectField(default=list)

	def get_api_url(self, request=None):
		return api_reverse("api-pages:mailbox-create", kwargs={'pk': self.id}, request=request)

	def get_absolute_url(self):
		return reverse("spam-settings", kwargs={"pk": self.id})

	def get_owner(self):
		return self.owner

class Mail(Message):
	"""Fields inherited from Message:
		id (AutoField) – Id
		mailbox_id (ForeignKey to Mailbox) – Mailbox
		subject (CharField) – Subject
		message_id (CharField) – Message id
		in_reply_to_id (ForeignKey to Message) – In reply to
		from_header (CharField) – From header
		to_header (TextField) – To header
		outgoing (BooleanField) – Outgoing
		body (TextField) – Body
		encoded (BooleanField) – True if the e-mail body is Base64 encoded
		processed (DateTimeField) – Processed
		read (DateTimeField) – Read
		eml (FileField) – Original full content of message
	"""
	spam = models.BooleanField(default=False)
	snippet = models.CharField(max_length=100)

	def get_absolute_url(self):
		return reverse("mail-detail", kwargs={"pk": self.id})

	def get_owner(self):
		obj = MailBox.objects.get(id=self.mailbox_id)
		return obj.owner

class Blacklist(models.Model):
	mailbox = models.ForeignKey(MailBox, on_delete=models.CASCADE)
	#mailbox_id = models.IntegerField()
	address = models.CharField(max_length=30)

	def get_owner(self):
		obj = MailBox.objects.get(id=self.mailbox)
		return obj.owner