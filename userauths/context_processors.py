from .models import UserProfile

# def profile_menu_links(request):
#     user = request.user
#     try:
#         user_profile = UserProfile.objects.get(user=user)
#     except UserProfile.DoesNotExist:
#         user_profile = None
#     links = user_profile.profile_picture if user_profile else None
#     return {'profile_picture': links}





def user_profile_links(request):
    user = request.user
    try:
        user_profile = UserProfile.objects.get(user=user)
    except UserProfile.DoesNotExist:
        user_profile = None
    links = user_profile.profile_picture if user_profile else None
    return {'profile_picture': links}