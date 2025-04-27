from django.contrib import admin
from .models import *
from django.utils.safestring import mark_safe

# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'email']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'address', 'display_profile_image', 'city', 'state', 'zipcode', 'bio']


    def display_profile_image(self, obj):
        if obj.profile_picture:
            return mark_safe('<img src="{}" width="50px" height="50px" />'.format(obj.profile_picture.url))
        return None    
    display_profile_image.short_description = 'Profile Picture'



@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ['token_id', 'token']