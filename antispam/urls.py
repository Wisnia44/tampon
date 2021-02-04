from django.urls import path
from .views import SpamView

app_name = 'antispam'
urlpatterns = [
	path('filter/', SpamView.as_view(), name='filter'),
	]
