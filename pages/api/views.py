from rest_framework import generics
from .serializers import MailBoxSerializer

class MailBoxCreateView (generics.CreateAPIView):
	lookup_field = 'pk'
	serializer_class = MailBoxSerializer

	def get_queryset(self):
		return MailBox.objects.all()
	
	def get_serializer_context(self, *args, **kwargs):
		return {"request": self.request}