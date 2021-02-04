from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from django import forms
from django.core.exceptions import ValidationError
from .models import MailBox, Blacklist

class UserCreationFormWithEmail (UserCreationForm):
	email = forms.EmailField(label='Gmail address')

	def save(self, commit=True):
		user = super(UserCreationFormWithEmail, self).save(commit=False)
		user.email = self.cleaned_data["email"]
		if commit:
			user.save()
		return user

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = [
        	'first_name', 
        	'last_name', 
        	'email', 
        	]
        exclude = (
        	'last_login',
        	'date_joined',
        	'is_superuser',
        	'is_active',
        	'is_staff',
        	'user_permissions',
        	'groups',
        	'password',
        	)

class MailBoxModelForm(forms.ModelForm):
    class Meta:
        model = MailBox
        fields = ['bayess_filter_sensibility']


class BlacklistModelForm(forms.ModelForm):
    class Meta:
        model = Blacklist
        fields = ['address']