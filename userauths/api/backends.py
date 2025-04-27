from django.contrib.auth.backends import BaseBackend
from userauths.models import User
from django.contrib.auth.hashers import check_password


class SQLiteBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        try:
            # Search for the user by email, as it's the USERNAME_FIELD in your User model
            user = User.objects.get(email=username)
            if user and check_password(password, user.password):  # Use Django's password checker
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
