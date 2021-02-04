from rest_framework import serializers
from pages.models import MailBox

class MailBoxSerializer(serializers.ModelSerializer):
	#url = serializers.SerializerMethodField(read_only=True)
	class Meta:
		model = MailBox
		fields = [
			'pk',
			'name',
			'uri',
			'owner',
			'from_email',
			'active',
			'last_polling',
		]

	def get_url(self, obj):
		request = self.context.get("request")
		return obj.get_api_url(request=request)
		