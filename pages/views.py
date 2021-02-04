from django.contrib.auth import logout, login, authenticate, update_session_auth_hash
from django.contrib.auth.forms import (
	UserCreationForm, 
	AuthenticationForm, 
	UserChangeForm, 
	PasswordChangeForm
	)
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from django.shortcuts import render, redirect, get_list_or_404
from django.urls import reverse
from django.http import HttpResponse, HttpRequest, HttpResponseRedirect
from django.core.exceptions import ValidationError

from django.views import View
from django.views.generic import (
	CreateView,
	DeleteView,
	DetailView,
	ListView,
	UpdateView,
	)

import pickle
import os.path
import json
import requests
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

from rest_framework import status
from rest_framework.reverse import reverse as api_reverse

from datetime import datetime

from .models import Mail, MailBox, Blacklist
from .forms import (
	UserCreationFormWithEmail, 
	UserUpdateForm, 
	MailBoxModelForm, 
	BlacklistModelForm,
	)




# User based views
class UserLoginView (View):
	template_name = 'pages/user_login.html'
	def post (self, request, *args, **kwargs):
		form = AuthenticationForm(data=request.POST)
		if form.is_valid():
			user = form.get_user()
			login(request, user)
			return redirect('home')
		else:
			return redirect('welcome')
	def get (self, request, *args, **kwargs):
		form = AuthenticationForm()
		return render(request, self.template_name, {'form': form})

class UserLogoutView (View):
	def post (self, request, *args, **kwargs):
		logout(request)
		return redirect('welcome')

class UserUpdateView (View):
	template_name = 'pages/user_update.html'
	model = User
	success_url = 'pages/user_update.html'
	def post (self, request, *args, **kwargs):
		form = UserUpdateForm(data=request.POST, instance=request.user)
		form.fields['first_name'].initial = request.user.first_name
		form.fields['last_name'].initial = request.user.last_name
		form.fields['email'].initial = request.user.email
		if form.is_valid():
			form.save()
		return redirect('home')
	def get(self, request, *args, **kwargs):
		form = UserUpdateForm()
		form.fields['first_name'].initial = request.user.first_name
		form.fields['last_name'].initial = request.user.last_name
		form.fields['email'].initial = request.user.email
		return render(request, self.template_name, {'form': form})	

class UserDeleteView (DeleteView):
	template_name = 'pages/user_delete.html'
	def get (self, request, *args, **kwargs):
		return render(request, self.template_name, {})
	def post(self, request, *args, **kwargs):
		user = User.objects.get(pk=request.user.pk)
		user.delete()
		return redirect('welcome') 

class UserSignupView (View):
	template_name = 'pages/user_signup.html'
	def post (self, request, *args, **kwargs):
		form = UserCreationFormWithEmail(request.POST)
		if form.is_valid():
			form.save()
			username = form.cleaned_data.get('username')
			raw_password = form.cleaned_data.get('password1')
			user = authenticate(username=username, password=raw_password)
			login(request, user)
			return redirect('create-mailbox')
		else:
			raise ValidationError

	def get (self, request, *args, **kwargs):
		form = UserCreationFormWithEmail()
		return render(request, self.template_name, {'form': form})

class UserChangePassword(View):
	template_name = 'pages/user_change_password.html'
	def post (self, request, *args, **kwargs):
		form = PasswordChangeForm(request.user, request.POST)
		if form.is_valid():
			user = form.save()
			update_session_auth_hash(request, user)
			return redirect('home')
	def get (self, request, *args, **kwargs):
		form = PasswordChangeForm(request.user)
		return render(request, self.template_name, {'form': form})


#Main views
class WelcomeView (View):
	template_name = 'pages/welcome.html'
	def get(self, request, *args, **kwargs):
		return render(request, self.template_name)

class HomeView (View):
	template_name = 'pages/home.html'
	def get(self, request, *args, **kwargs):
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		return render(request, self.template_name, {"mailbox": mailbox})

class AnonymousUserView (View):
	template_name = 'pages/anonymous_user.html'
	def get(self, request, *args, **kwargs):
		return render(request, self.template_name)

class NotOwnerView (View):
	template_name = 'pages/not_owner.html'
	def get(self, request, *args, **kwargs):
		return render(request, self.template_name)


#Blacklist based views
class BlacklistCreateView(CreateView):
	template_name = 'pages/blacklist_create.html'
	form_class = BlacklistModelForm
	queryset = Blacklist.objects.all()

	def get (self, request, *args, **kwargs):
		form = BlacklistModelForm()
		return render(request, self.template_name, {'form': form})

	def get_success_url(self):
		return reverse('home')

	def form_valid(self, form):
		obj = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		form.instance.mailbox = obj
		return super(BlacklistCreateView, self).form_valid(form)

class BlacklistUpdateView(UpdateView):
	template_name = 'pages/blacklist_create.html'
	form_class = BlacklistModelForm
	queryset = Blacklist.objects.all()

	def get (self, request, *args, **kwargs):
		form = BlacklistModelForm()
		return render(request, self.template_name, {'form': form})

	def get_success_url(self):
		return reverse('home')

class BlacklistDeleteView(DeleteView):
	template_name = 'pages/blacklist_delete.html'
	queryset = Blacklist.objects.all()

	def get (self, request, *args, **kwargs):
		form = BlacklistModelForm()
		return render(request, self.template_name, {'form': form})

	def get_success_url(self):
		return reverse('home')


#MailBox based views
class CreateMailBoxView(View):
	def get(self, request, *args, **kwargs):
		email = request.user.email.replace('@gmail.com','')
		new_mailbox = MailBox.objects.get_or_create(
			name=email, 
			uri=f'gmail+ssl://{email}%40gmail.com:oauth2@imap.gmail.com?archive=Archived',
			owner=request.user
			)
		return redirect ('home')

class MailBoxBayessUpdateView(UpdateView):
	template_name = 'pages/mailbox_bayess_update.html'
	form_class = MailBoxModelForm
	queryset = MailBox.objects.all()

	def get_success_url(self):
		return reverse('home')

class SpamSettingsView(View):
	template_name = "pages/spam_settings.html"

	def get (self, request, *args, **kwargs):
		obj = MailBox.objects.get(id=kwargs["pk"])
		blacklist = list(Blacklist.objects.filter(mailbox=obj))
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		if not blacklist:
			blacklist = None
		return render(request, self.template_name, {"object": obj, "blacklist":blacklist, "mailbox": mailbox})

	def get_context_data(self, **kwargs):
		context = super(SpamSettingsView, self).get_context_data(**kwargs)
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		context['mailbox'] = mailbox
		return context

class SpamStatsView(View):
	template_name="pages/spam_stats.html"
	def get (self, request, *args, **kwargs):
		obj = MailBox.objects.get(id=kwargs["pk"])
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		return render(request, self.template_name, {"object": obj, "mailbox": mailbox})

	def get_context_data(self, **kwargs):
		context = super(SpamStatsView, self).get_context_data(**kwargs)
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		context['mailbox'] = mailbox
		return context


#Mail based views
class MailListView(ListView):
	template_name = 'pages/mail_list.html'

	def get_queryset(self):
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		return Mail.objects.filter(mailbox_id=mailbox.id, spam=False).values()

	def get_context_data(self, **kwargs):
		context = super(MailListView, self).get_context_data(**kwargs)
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		context['mailbox'] = mailbox
		return context

class SpamListView(ListView):
	template_name = 'pages/spam_list.html'

	def get_queryset(self):
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		return Mail.objects.filter(mailbox_id=mailbox.id, spam=True).values()

	def get_context_data(self, **kwargs):
		context = super(SpamListView, self).get_context_data(**kwargs)
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		context['mailbox'] = mailbox
		return context

class MailGetView(ListView):
	template_name = 'pages/get_mail.html'

	def get(self, request, *args, **kwargs):
		creds = None
		script_dir = os.path.dirname(__file__)
		email = request.user.email.replace('@gmail.com','')
		file_name  = "token_" + email + ".pickle"
		file_rel_path = "tokens/" + file_name
		file_abs_path = os.path.join(script_dir, file_rel_path)
		print(file_abs_path)
		if os.path.exists(file_abs_path):
			with open(file_abs_path, 'rb') as token:
				creds = pickle.load(token)
		if not creds or not creds.valid:
			if creds and creds.expired and creds.refresh_token:
				creds.refresh(Request())
			else:
				flow = InstalledAppFlow.from_client_secrets_file(
					'credentials.json',
					['https://www.googleapis.com/auth/gmail.readonly']
					)
				creds = flow.run_local_server(port=8080)
			with open(file_abs_path, 'wb') as token:
				pickle.dump(creds, token)

		#credentials_delegated = creds.with_subject(user[request.uder.email])
		service = build('gmail', 'v1', credentials=creds)
		results = service.users().messages().list(userId=request.user.email, labelIds=['INBOX']).execute()
		messages = results.get('messages', [])

		if messages:
			email = request.user.email.replace('@gmail.com','')
			mailbox = MailBox.objects.filter(name=email)
			blacklist_2 = Blacklist.objects.filter(mailbox=mailbox[0])
			blacklist = []
			for element in blacklist_2:
				blacklist.append(element.address)
			history_id = mailbox[0].history_id
			for message in messages:
				msg = service.users().messages().get(
					userId=request.user.email,
					id=message['id'],
					format="full",
					metadataHeaders=None
					).execute()
				headers_raw = msg['payload']['headers']
				headers = {}
				for header in headers_raw:
					headers[header['name']] = header['value']
				if int(msg['historyId'])>mailbox[0].history_id:
					history_id  = max(int(msg['historyId']),history_id)
					to = headers["To"]
					fromm = headers["From"]
					subject = headers['Subject']
					if fromm.find('<') != -1:
						email_from = fromm[fromm.find('<')+1:fromm.find('>')]
					else:
						email_from = fromm
					print(email_from)
					try:
						obj = Mail.objects.get(
							mailbox_id=mailbox[0].id,
							subject=subject,
							from_header=fromm,
							to_header=to
							)
					except Mail.DoesNotExist:
						url = 'http://127.0.0.1:8000/antispam/filter/'
						headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
						post_data = {'email_body': msg['snippet'],
							'email_from': email_from,
							'sensitivity': mailbox[0].bayess_filter_sensibility,
							'blacklist': blacklist
							}
						post_json = json.dumps(post_data)
						response = requests.post(url, data=post_json, headers=headers)
						response_content = bool(int(str(response.content, 'utf-8')))
						obj = Mail(
							mailbox_id=mailbox[0].id,
							subject=subject,
							from_header=fromm,
							to_header=to,
							message_id=msg['id'],
							body=msg['payload']['body'],
							#eml=msg['raw'],
							spam=response_content,
							snippet=msg['snippet']
							)
						obj.save()
						x = mailbox[0].received_counter + 1
						if response_content == True:
							y = mailbox[0].spam_counter + 1
						else:
							y = mailbox[0].spam_counter
						mailbox.update(received_counter=x, spam_counter=y)
						mailbox[0].refresh_from_db()

			mailbox.update(history_id=history_id)
			mailbox[0].refresh_from_db()

		return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

class FilterAPITestView(View):
	def get(self, request, *args, **kwargs):
		url = 'http://127.0.0.1:8000/antispam/filter/'
		headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
		post_data = {'email_body': "tekst wiadomosci, tekst wiadomosci, tekst, tekst, tekst, xdd",
						'email_from': "xdd@gmail.com",
						'sensitivity': "low",
						'blacklist': ["abc@gmail.com", "xd@gmail.com"]
						}
		post_json = json.dumps(post_data)
		response = requests.post(url, data=post_json, headers=headers)
		content = int(str(response.content, 'utf-8'))
		return redirect('welcome')

class MailDetailView(DetailView):
	template_name = 'pages/mail_detail.html'

	def get_queryset(self):
		return Mail.objects.all()

	def get_context_data(self, **kwargs):
		context = super(MailDetailView, self).get_context_data(**kwargs)
		mailbox = MailBox.objects.get(
			name=self.request.user.email.replace('@gmail.com',''),
			owner=self.request.user
			)
		context['sensitivity'] = mailbox.bayess_filter_sensibility 
		blacklist_2 = Blacklist.objects.filter(mailbox=mailbox)
		blacklist = []
		for element in blacklist_2:
			blacklist.append(element.address)
		context['blacklist'] = blacklist
		return context

class MailDeleteView(DeleteView):
	template_name = 'pages/mail_delete.html'
	queryset = Mail.objects.all()

	def get_success_url(self):
		return reverse('mail-list')

class MailChangeSpamLabelView(View):
	template_name = 'pages/mail_change_spam_label.html'

	def get(self, request, *args, **kwargs):
		queryset = Mail.objects.filter(id=kwargs["pk"])
		context = {"subject": queryset[0].subject,
			"from_header": queryset[0].from_header
			}
		return render(request, self.template_name, context)

	def post(self, request, *args, **kwargs):
		obj = Mail.objects.filter(id=kwargs["pk"])
		mailbox = MailBox.objects.filter(id=obj[0].mailbox_id)
		if obj[0].spam == True:
			x = mailbox[0].spam_counter - 1
			obj.update(spam=False) 
			mailbox.update(spam_counter=x)
		else:
			x = mailbox[0].spam_counter + 1
			obj.update(spam=True)
			mailbox.update(spam_counter=x)
		obj[0].refresh_from_db()
		mailbox[0].refresh_from_db()
		ad = obj[0].get_absolute_url()
		return redirect(ad)
		