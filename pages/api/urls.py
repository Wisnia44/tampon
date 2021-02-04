from django.conf.urls import url
from .views import MailBoxCreateView

app_name = 'api-pages'
urlpatterns = [
	url(r'^$', MailBoxCreateView.as_view(), name='mailbox-create'),
]
