from rest_framework import serializers

class FilterSerializer(serializers.Serializer):

    email_body = serializers.CharField()
    email_from = serializers.EmailField()
    sensitivity = serializers.ChoiceField(choices=["low", "medium", "high"])
    blacklist = serializers.ListField(child=serializers.EmailField())
