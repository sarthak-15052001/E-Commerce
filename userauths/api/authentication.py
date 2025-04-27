from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.settings import api_settings
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import AuthenticationFailed
from userauths.models import User             # Import your Django ORM models
from rest_framework_simplejwt.exceptions import InvalidToken



class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        """
        Override the default get_user method to fetch the user from the SQLite database.
        """
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError:
            raise AuthenticationFailed(_("Token contained no recognizable user identification"))

        try:
            # Fetch the user using Django ORM
            user = User.objects.get(pk=user_id)
            if not user.is_active:
                raise AuthenticationFailed(_("User account is inactive"))
        except User.DoesNotExist:
            raise AuthenticationFailed(_("User not found"))

        return user
