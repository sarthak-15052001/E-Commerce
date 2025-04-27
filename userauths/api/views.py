from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, serializers, status, viewsets, filters
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.views import TokenRefreshView
from drf_yasg import openapi
from E_Commerce_Website.app_helpers import CustomResponse
from userauths.api import serializers as userauths_serializer
from userauths.models import User
from django.shortcuts import render
from django.contrib import messages
from django.views import View
from userauths.api.forms import ResetPasswordForm
from django.core.mail import send_mail
import uuid
from django.conf import settings
from userauths.models import *
from E_Commerce_Website.permissions import IsSuperuser
from core.models import *
from userauths.models import *
from django.db.models import Q
from userauths.api import pagination
from django_filters.rest_framework import DjangoFilterBackend
from datetime import datetime
from rest_framework.filters import OrderingFilter



#<---------------------------------User Auths Starts From Here---------------------------->

#<---------------------------------Signup View Starts From Here---------------------------->
class SignupView(generics.CreateAPIView):
    """
    View for handling user signup.
    """
    permission_classes = [AllowAny]
    serializer_class = userauths_serializer.UserSerializer    # Ensure this serializer handles User creation

    @swagger_auto_schema(
        operation_description="User signup endpoint",
        responses={201: "User created successfully", 400: "Bad request"},
        tags=["UserAuth API"],
    )
    def post(self, request, *args, **kwargs):
        """
        Custom post method to handle user signup.
        """
        try:
            serializer = self.get_serializer(data=request.data) # Retrieves an instance of the UserSerializer with the data from the request (request.data).
            serializer.is_valid(raise_exception=True)            # Validates the input data against the rules defined in the UserSerializer
                                                                 # f the data is invalid: A serializers.ValidationError is raised, which will be handled in the except block

            serializer.save()                                # Creates a new user in the database using the validated data.

            return CustomResponse.success(                   # Return a success response
                message="Email verification link sent on your email id."
            )
        except serializers.ValidationError as e:                 # Handle validation errors
            # Extract the first error message from the dictionary
            error_messages = []
            for field, messages in e.detail.items():
                if isinstance(messages, list):
                    error_messages.extend(messages)
                else:
                    error_messages.append(messages)

             # Return only the first error message if there are multiple
            return CustomResponse.error(
                message=error_messages[0] if error_messages else "Validation error."
            )
    
        except Exception as e:                                   # Handle any other exceptions
            return CustomResponse.error(
                message=f"An unexpected error occurred: {str(e)}"
            )
        
#<---------------------------------Login API View Starts From Here------------------------------>
class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = userauths_serializer.CustomTokenObtainPairSerializer


    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)    # Prepares the serializer to validate the input data (e.g., email, password).
        try:
            serializer.is_valid(raise_exception=True)         # Validates the input data against the rules defined in the serializer.
            return CustomResponse.success(
                message=serializer.validated_data["message"],  # Extracts the "message" key from the serializer's validated_data, which likely contains a login success message.    
                data=serializer.validated_data["data"],        # Extracts the "data" key from the serializer's validated_data, which might include: Access and refresh tokens, User information like email, name, etc.
            )
        except serializers.ValidationError as e:    # Catches validation errors raised by the serializer.is_valid() method. This exception occurs if:-  The login credentials are incorrect. Required fields (e.g., email or password) are missing. Other validation rules in the serializer fail.
            error_message = e.detail.get("message", ["Validation error."])[0]
            return CustomResponse.error(
                message=error_message
            )

'''
e.detail:
Contains the error details as a dictionary. For example:
{"message": ["Invalid credentials."]}
get("message", ["Validation error."]):
Tries to fetch the "message" key from the error details.
If "message" is not present, defaults to ["Validation error."].
[0]:
Extracts the first message from the list of error messages.

CustomResponse.error:
Returns a standardized error response.
Message:
Uses the extracted error_message to inform the client about what went wrong.
Example: "Invalid credentials."

'''


#<--------------------------------VerifyEmailView Starts From Here----------------------------->
class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="User Email Verification",
        responses={404: "Token not found", 200: "Email verified successfully"},
        tags=["UserAuth API"],
    )
    def get(self, request, token, *args, **kwargs):
        try:
            # Search for the user with the given token
            user = User.objects.filter(email_token=token).first()   # Looks for a user in the User model whose email_token matches the provided token and returns a queryset of all matching with the first users in the queryset or None if no match found
            print('user: ', user)

            if not user:                 # If no user is found (user is None), it means the token is invalid or expired.
                return render(
                    request, "api/token_not_found.html", status=status.HTTP_404_NOT_FOUND   # Renders the token_not_found.html template with a 404 Not Found status.
                )
            print(">>>>>>>>>>>>>>>>>>>>>.")
            # Check if the user is already verified
            if user.email_verified:
                # Render the `email_verified.html` template with a custom message for already-verified users
                return render(
                    request,
                    "api/email_verified.html",
                    {"message": "Your email has already been verified."}
                )

            # Set email as verified and save the user
            user.email_verified = True                 # Sets the email_verified field of the user object to True.
            user.save()                                # Persists the changes to the database
            print("---------------------")

            return render(
                request,
                "api/email_verified.html",
                {"message": "Email verified successfully!"},
            )

        except Exception as e:
            # Log the exception for debugging purposes
            print(f"Error verifying email: {e}")
            # Use CustomResponse without the `status` argument
            return CustomResponse.error(message="Server error")



#<---------------------Refresh Token View Starts From Here------------------------------->
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):   # Overrides the post method of the parent TokenRefreshView class to customize the response.
        # Call the parent class's post method to get the original response
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            return CustomResponse.success(
                message="Access token generated",
                data={"access_token": response.data.get("access")},
            )

        return CustomResponse
    

#<--------------------------Change Password View Starts From Here---------------------------->
class ChangePassword(generics.GenericAPIView):
    serializer_class = userauths_serializer.ChangePasswordSerializer
    Permission_classes = [IsAuthenticated]


    @swagger_auto_schema(
        operation_description="partial update description override",
        responses={404: "slug not found", 200: "not found"},
        tags=["UserAuth API"],
    )
    def post(self, request, *args, **kwargs):
        try:
            user = request.user    # Retrieves the currently authenticated user making the request
            serializer = self.get_serializer(data=request.data, context={"user": user})   # Creates an instance of the ChangePasswordSerializer and passes the user's data (request.data) for validation. Adds the currently authenticated user (user) to the serializer's context for custom validation logic

            serializer.is_valid(raise_exception=True)   # Validates the data passed to the serializer. If validation fails, it raises a serializers.ValidationError.

            # user = request.user
            user.set_password(serializer.validated_data["password"])  # Uses the set_password method of the User model to securely hash and update the user's password. serializer.validated_data["password"]:- Retrieves the validated new password from the serializer.
            user.save()                                               # Saves the updated user instance to the database, applying the new password.
            return CustomResponse.success(message="Password Changed Successfully.")
        
        except serializers.ValidationError as e:          # Catches validation errors raised during the is_valid step. Ensures a custom error response is returned instead of the default one.
            # Catch validation errors and send a custom response
            return CustomResponse.error(
                message=e.detail.get("message")[0]
                if e.detail.get("message")
                else "Validation error."
            )
        
'''
Creates a custom error response using CustomResponse.error.
Error Message Handling:
Checks if the validation error contains a "message" key in its details.
If "message" exists, retrieves the first error message (e.detail.get("message")[0]).
If not, defaults to "Validation error.
'''

#<---------------------------------Forget Password View Starts From Here------------------------->
class ForgetPasswordView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = userauths_serializer.ForgetPasswordSerializer

    @swagger_auto_schema(
        operation_description="partial_update description override",
        responses={404: "slug not found", 200: "not found"},
        tags=["UserAuth API"],
    )
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)             # Creates an instance of the ForgetPasswordSerializer and validates the incoming data (request.data).
            serializer.is_valid(raise_exception=True)                       # Raises a serializers.ValidationError if the data is invalid
            email = serializer.validated_data["email"]                      # etrieves the validated email address from the serializer

            # Check if user exists
            try:
                user = User.objects.get(email=email)          # Looks for a user in the database with the provided email.
            except User.DoesNotExist:                         # If no user is found, it returns an error response.
                return CustomResponse.error(  
                    message="User with this email does not exist."
                )

            # Generate a unique email token
            user.email_token = str(uuid.uuid4())                            # Generates a unique token using uuid.uuid4() to identify the password reset request.
            user.save()                                                     # Saves the token to the user's record in the database.
 
            # Construct the reset link
            reset_link = f"{settings.USER_BASE_URL}reset-password/{user.email_token}"       # reates a password reset link by appending the user's unique email token to the base URL defined in the settings

            # Send the email
            subject = "Password Reset Request"
            message = f"Hi {user.first_name},\n\nPlease click the link below to reset your password:\n{reset_link}\n\nIf you did not request this, please ignore this email."
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email]
            send_mail(subject, message, email_from, recipient_list)

            return CustomResponse.success(
                message="Password reset link sent to your email."
            )
        except serializers.ValidationError:
            return CustomResponse.error(message="Invalid email format.")
        except Exception as e:
            return CustomResponse.error(
                message=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

#<---------------------------------------Reset Password View Starts From Here--------------->
'''
enders the reset_password.html template for the user.
Passes the following context to the template:
form: The password reset form instance.
token: The token passed in the URL, which will be required for password reset validation.
'''

class ResetPasswordView(View):
    def get(self, request, token=None):
        form = ResetPasswordForm()               # Creates an instance of the ResetPasswordForm, which is likely a Django forms.Form class for resetting the user's password.
        return render(request, "api/reset_password.html", {"form": form, "token": token})

    def post(self, request, token=None):
        form = ResetPasswordForm(request.POST)           # Creates an instance of the ResetPasswordForm, populating it with data from the submitted POST request.
        if form.is_valid():                              # If valid, the execution continues. If not, the view skips the if block and re-renders the form with errors.
            password = form.cleaned_data["password"]     # Retrieves the cleaned password field from the form's validated data.
            try:
                # Fetch the user using the token
                user = User.objects.get(email_token=token)    # Tries to fetch the user from the database using the provided email_token. Queries the User model for a record where the email_token matches the provided token.
                print('-----------------------user: ', user)
                user.set_password(password)  # Use Django's set_password method. Updates the user's password using Django's built-in set_password method. This method ensures the password is securely hashed before saving it to the database.

                user.email_token = None  # Invalidate the token after reset. Clears the email_token field to prevent reuse of the same token for future password resets.
                user.save()              # Saves the updated user object to the database, persisting the new password and invalidated token.
                print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
                messages.success(request, "Password has been reset successfully.")
                # return render(request, "login.html")  # Redirect to login page

            except User.DoesNotExist:                   # Handles cases where no user is found with the provided token.
                messages.error(request, "Invalid token or user does not exist.")
        return render(request, "api/reset_password.html", {"form": form, "token": token})


#<----------------------------Signout View Starts From Here------------------------------->
class SignoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = userauths_serializer.SignoutSerializer

    @swagger_auto_schema(
        operation_description="Log out the user by blacklisting their refresh token.",
        request_body=userauths_serializer.SignoutSerializer,
        responses={
            200: "User logged out successfully.",
            400: "Refresh token missing or invalid token.",
        },
        tags=["UserAuth API"],
    )
    def post(self, request, *args, **kwargs):
        """
        Log out the user by blacklisting their refresh token.
        """
        try:
            user = request.user                   # Fetches the currently authenticated user from the request.

            # Get the refresh token from the request data
            access_token = request.data.get("access_token")   # Retrieves the access_token from the request's body data.    

            if access_token:         # Check If Access Token Exists
                # Validate the token
                token = AccessToken(access_token)   # Attempts to validate the provided access_token using Django's AccessToken class. If the token is invalid or expired, this will raise an exception.

                # Save the token in the SQLite database
                BlacklistedToken.objects.create(token=str(token))      # Stores the validated token in the BlacklistedToken table to mark it as invalid. Prevents further use of this token for authentication.

                # user.device = None
                user.save()                                            # Saves the current state of the user object in the database.

                return CustomResponse.success(message="Logged out successfully.")        # Returns a success response with the message Logged out successfully. if the token was successfully blacklisted and the operation completed.
            else:
                return CustomResponse.error(message="Access token missing.")
        except Exception:
            return CustomResponse.error(message="Invalid token or token expired.")
        

#<-------------------------Admin APIS Starts From Here---------------------------------->

#<-------------------------Admin Profile Views Starts From Here------------------------------>
class AdminProfileView(generics.GenericAPIView):
    serializer_class = userauths_serializer.AdminProfileSerializer
    permission_classes = [IsSuperuser]
    parser_classes = [MultiPartParser, FormParser]


    @swagger_auto_schema(
        operation_description="Admin profile endpoint",
        responses={200: "Profile retrieve successfully.", 400: "User not found"},
        tags=["Admin API"],
    )
    def get(self, request, *args, **kwargs):
        # Fetch only profiles associated with superusers
        profile = UserProfile.objects.select_related('user').filter(user__is_superuser=True) # Queries the UserProfile model for profiles associated with superusers. Uses select_related('user') to optimize database queries by joining related User data.

    
        if profile.exists():    # Checks whether any profiles matching the query exist. If no profiles are found, the method will return an error response.
            serializer = self.get_serializer(profile, many=True)
            return CustomResponse.success(
                message="Profiles retrieved successfully.", data=serializer.data
            )
        return CustomResponse.error(message="No profiles found.")
    

    @swagger_auto_schema(
        operation_description="Admin update profile endpoint",
        request_body=userauths_serializer.AdminProfileSerializer,
        responses={200: "Profile updated successfully.", 400: "Invalid data provided."},
        tags=["Admin API"],
    )
    def put(self, request, *args, **kwargs):
        user = request.user                     # Retrieves the currently authenticated user from the request.

        # Ensure the user is a superuser
        if not user.is_superuser:      # Ensures the user is a superuser. Returns an error response with a 403 Forbidden status if the user lacks the required permissions.
            return CustomResponse.error(message="Permission Denied.", status=403)
        
        try:
            # Fetch the admin's UserProfile instance
            profile = UserProfile.objects.get(user=user)           # Attempts to retrieve the UserProfile associated with the authenticated user.
        except UserProfile.DoesNotExist:
            return CustomResponse.error(message="Profile not found.", status=404)      # Returns an error response with a 404 Not Found status if no profile is found.
        
        serializer = self.get_serializer(data=request.data, instance=profile)  # Initializes the serializer with the incoming request data and the existing profile (instance=profile).
        serializer.is_valid(raise_exception=True)             # Validates the data. If validation fails, an exception is raised, and a 400 Bad Request response is returned.

        # Save the updated profile
        serializer.update(instance=profile, validated_data=serializer.validated_data)     # Updates the existing profile with the validated data from the serializer.
        return CustomResponse.success(message="Profile updated successfully.", data=serializer.data)                


'''
What Does instance=profile Do?
The instance argument is used to provide the serializer with an existing model instance (profile in this case) that needs to be updated.
Without instance, the serializer assumes you're creating a new object (default behavior).
By passing instance=profile, you're telling the serializer:
"Don't create a new profile. Instead, update the existing profile with the provided data."
'''


#<----------------------------With Serializer Implemented----------------------------->

#<----------------------------Admin Dashboard API View Starts From Here--------------------------->
class AdminDasboardAPIView(APIView):
    """
    API endpoint for fetching admin dashboard data.
    """
    permission_classes = [IsSuperuser]

    @swagger_auto_schema(
        operation_description="Dashboard data verification",
        responses={200: "Dashboard data fetched successfully.", 400: "Bad request"},
        tags=["Admin API"],
    )
    def get(self, request, *args, **kwargs):
        # Fetch Statistics
        total_category = Category.objects.count()    # Retrieves the total number of categories by counting all records in the Category model.
        total_products = Product.objects.count()     # Retrieves the total number of products by counting all records in the Product model.
        total_customers = User.objects.filter(is_active=True, is_staff=False).count()  # is_active=True: Only considers active users. # is_staff=False: Excludes staff/admin accounts. Counts the remaining users as "customers."
        total_orders = Order.objects.count()       # Retrieves the total number of orders by counting all records in the Order model.


        # Prepare data
        data = {                            # Creates a dictionary called data containing the fetched statistics:
            "total_category": total_category,
            "total_products": total_products,
            "total_customers": total_customers,
            "total_orders": total_orders,
        }

        # Debug the data being passed
        print("DEBUG: Data being passed to serializer:", data)

        # Serialize and return data
        serializer = userauths_serializer.AdminDashboardSerializer(data=data)         # A serializer class responsible for validating and formatting the dashboard data.
        serializer.is_valid(raise_exception=True)
        return Response({"success": True, "data": serializer.data}, status=200)


# <--------------------------------Without Serializer Implemented---------------------------->
# class AdminDasboardAPIView(APIView):
#     """
#     API endpoint for fetching admin dashboard data.
#     """
#     permission_classes = [IsSuperuser]  # Only allow admin users

#     @swagger_auto_schema(
#         operation_description="Dashbord data Verification",
#         responses={400: "Bad request", 200: "Dashboard data fetched successfully."},
#         tags=["Admin API"],
#     )
#     def get(self, request, *args, **kwargs):
#         user = request.user

#         # Fetch statistics
#         total_category = Category.objects.count()
#         total_products = Product.objects.count()
#         total_customers = User.objects.filter(is_active=True, is_staff=False).count()
#         total_orders = Order.objects.count()

#         # # Fetch user profile
#         # try:
#         #     user_profile = UserProfile.objects.get(user=user)
#         #     profile_picture = user_profile.profile_picture.url if user_profile.profile_picture else None
#         # except UserProfile.DoesNotExist:
#         #     profile_picture = None

#         # Construct response
#         data = {
#             "total_category": total_category,
#             "total_products": total_products,
#             "total_customers": total_customers,
#             "total_orders": total_orders,
#             # "profile_picture": profile_picture,
#         }

#         return Response({"success": True, "data": data}, status=200)


#<----------------------Admin Customer Viewset Starts From Here---------------------------------->
class AdminCustomerViewSet(viewsets.GenericViewSet):
    """
    A viewset that provides custom `retrieve` and `list` actions.
    """
    queryset = User.objects.all()   # Specifies the base queryset as all User model objects.
    serializer_class = userauths_serializer.AdminCustomerSerializer
    permission_classes = [IsSuperuser]                   # Or use your custom IsSuperuser permission
    pagination_class = pagination.UserPagination         # Specifies a custom pagination class to handle paginated responses for the list action. 
    filter_backends = [                                  # Specifies backends for filtering and ordering:
        DjangoFilterBackend,                             # Enables filtering using query parameters.
        # filters.SearchFilter,
        filters.OrderingFilter,                          # Allows ordering results by specified fields.
    ]
    search_fields = [
        "id",
        "username",
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "userprofile__city",
        "userprofile__state",
        "userprofile__bio",
    ]
    ordering_fields = [
        "id",
        "username",
        "first_name",
        "last_name",
        "email",
        "phone_number",
        "userprofile__city",
        "userprofile__state",
        "is_active",
    ]
    ordering = ["username"]                # Sets the default ordering of results by username.
   
    def get_queryset(self):
        """
        Filters out superuser accounts from the queryset.
        """
        queryset = super().get_queryset().filter(is_superuser=False)         # Overrides the base queryset to exclude superusers by applying a filter
        return queryset

    @swagger_auto_schema(
        operation_description="Retrieve a single user by ID",
        responses={200: userauths_serializer.AdminCustomerSerializer, 404: "User not found.", 400: "Bad request."},
        tags=["Admin API"],
    )
    def retrieve(self, request, pk=None):
        """
        Retrieves a single user by ID.
        """
        try:
            user = self.get_queryset().get(pk=pk)       # Attempts to fetch the user from the filtered queryset using get(pk=pk).
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)        # Returns a 404 response if the user is not found.

        serializer = self.serializer_class(user)                    # Serializes the user data using the defined serializer class.
        return Response(serializer.data, status=status.HTTP_200_OK)      # Returns the serialized user data with a 200 OK status.
 

    @swagger_auto_schema(
        operation_description="List all users with optional filters for name, state, city, and bio.",
        manual_parameters=[
            openapi.Parameter(
                "name", openapi.IN_QUERY, 
                description="Search by first or last name.", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                "state", openapi.IN_QUERY, 
                description="Search by state.", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                "city", openapi.IN_QUERY, 
                description="Search by city.", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                "bio", openapi.IN_QUERY, 
                description="Search by user profile bio.", 
                type=openapi.TYPE_STRING
            ),
        ],
        responses={200: userauths_serializer.AdminCustomerSerializer(many=True), 400: "Bad request."},
        tags=["Admin API"],
    )
    def list(self, request):
        """
        Lists all users with optional filters.
        """
        queryset = self.get_queryset()

        # Fetch search parameters
        name_search = request.query_params.get("name", None)
        state_search = request.query_params.get("state", None)
        city_search = request.query_params.get("city", None)
        bio_search = request.query_params.get("bio", None)

        # Filter by name if provided 
        if name_search:
            queryset = queryset.filter(
                Q(first_name__icontains=name_search) |
                Q(last_name__icontains=name_search)
            )

        # Filter by state
        if state_search:
            queryset = queryset.filter(userprofile__state__icontains=state_search)

        # Filter by city
        if city_search:
            queryset = queryset.filter(userprofile__city__icontains=city_search)

        # Filter by Bio
        if bio_search:
            queryset = queryset.filter(userprofile__bio__icontains=bio_search)

        # Apply dynamic ordering
        ordering_param = request.query_params.get("ordering", None)

        if ordering_param:
            # Handle ascending or descending order based on the param
            if ordering_param == "a":  # Ascending order by username
                queryset = queryset.order_by("username")
            elif ordering_param == "z":  # Descending order by username
                queryset = queryset.order_by("-username")
            else:
                # Validate fields specified in the ordering param
                valid_ordering_fields = [field for field in ordering_param.split(",") if field.lstrip("-") in self.ordering_fields]
                if valid_ordering_fields:
                    queryset = queryset.order_by(*valid_ordering_fields)
                else:
                    # Fallback to default ordering if no valid fields
                    queryset = queryset.order_by(*self.ordering)
        else:
            # Default ordering
            queryset = queryset.order_by(*self.ordering)

        # Pagination
        page = self.paginate_queryset(queryset)   # A built-in method from Django REST Framework (DRF) provided by GenericViewSet or APIView.
        if page is not None:                      # Checks whether the self.paginate_queryset(queryset) method returned a paginated page.
            serializer = self.serializer_class(page, many=True)   # Serializes the paginated data (page) using the specified serializer_class.
            return self.get_paginated_response(serializer.data)   # A helper method provided by DRF that constructs a paginated response.

        serializer = self.serializer_class(queryset, many=True)       # This line is executed only if page is None, meaning pagination is not applied.
        return Response(serializer.data, status=status.HTTP_200_OK)
    

#<-------------------------Admin Order ViewSets Starts From Here--------------------------------->
class AdminOrderViewSet(viewsets.GenericViewSet):
    """
    A viewset for admin operations on orders.
    """
    queryset = Order.objects.all()
    serializer_class = userauths_serializer.AdminOrderSerializer
    permission_classes = [IsSuperuser]              # Replace with your custom permission class if needed
    pagination_class = pagination.PageNumberPagination
    filter_backends = [
        DjangoFilterBackend,
        # filters.SearchFilter,
        filters.OrderingFilter,
    ]
    search_fields = [
        # "id",
        "first_name",
        "last_name",
        "phone_number",
        "order_id"
    ]
    ordering_fields = [
        # "id",
        "first_name",
        "last_name",
        "total_amount",
        "made_on",
    ]
    ordering = ['first_name']        # Default ordering



    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'first_name', openapi.IN_QUERY, 
                description="Filter by First Name", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'made_on', openapi.IN_QUERY, 
                description="Filter by Made On", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'order_id', openapi.IN_QUERY, 
                description="Filter by Order ID", 
                type=openapi.TYPE_STRING
            ),
        ],
        tags=["Admin API"],
        responses={
        200: "Orders List retrieved successfully.",
        400: "Bad request.",
        },
    )
    def list(self, request):
        """
        Lists all orders with their payment details.
        """
        queryset = self.get_queryset()

        # Apply filters if needed
        first_name = request.query_params.get("first_name", None)
        made_on = request.query_params.get("made_on", None)
        order_id = request.query_params.get("order_id", None)

        if first_name:
            queryset = queryset.filter(first_name__istartswith=first_name)
            print('==============queryset: ', queryset)

            # Check if no results are found after filtering by first_name
            if not queryset.exists():
                return CustomResponse.error(
                    f"No orders found for the first name starting with '{first_name}'.",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
        if made_on:
            try:
                # Convert the string input into a date object
                made_on_date = datetime.strptime(made_on, "%Y-%m-%d").date()
                print('>>>>>>>>>made_on_date: ', made_on_date)

                # Handle timezone-aware datetime filtering (if required)
                queryset = queryset.filter(orderproduct__payment__made_on__date=made_on_date)

                # If the queryset is empty after filtering by date, return a custom message
                if not queryset.exists():
                    return CustomResponse.error(
                        f"No orders found for the date {made_on_date}.",
                        status_code=status.HTTP_404_NOT_FOUND
                    )

            except ValueError:
                return CustomResponse.error(
                    "Invalid date format. Please enter a date in the correct format (YYYY-MM-DD).",
                    status_code=status.HTTP_400_BAD_REQUEST
                )

        if order_id:
            queryset = queryset.filter(orderproduct__payment__order_id=order_id)

            # Check if no results are found after filtering by order_id
            if not queryset.exists():
                return CustomResponse.error(
                    f"No orders found for the order ID '{order_id}'.",
                    status_code=status.HTTP_404_NOT_FOUND
                )

        # Ensure we only get orders with associated payments
        queryset = queryset.filter(orderproduct__payment__isnull=False)

        # Apply dynamic ordering
        ordering_param = request.query_params.get("ordering", None)

        if ordering_param:
            # Handle ascending or descending order based on the param
            if ordering_param == "a":  # Ascending order by username
                queryset = queryset.order_by("first_name")
            elif ordering_param == "z":  # Descending order by username
                queryset = queryset.order_by("-first_name")
            else:
                # Validate fields specified in the ordering param
                valid_ordering_fields = [field for field in ordering_param.split(",") if field.lstrip("-") in self.ordering_fields]
                if valid_ordering_fields:
                    queryset = queryset.order_by(*valid_ordering_fields)
                else:
                    # Fallback to default ordering if no valid fields
                    queryset = queryset.order_by(*self.ordering)
        else:
            # Default ordering
            queryset = queryset.order_by(*self.ordering)


        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Return success response with serialized data
        serializer = self.serializer_class(queryset, many=True)
        return CustomResponse.success(
            message="Orders List retrieved successfully.",
            data=serializer.data
        )

    @swagger_auto_schema(
        operation_description="Retrieve an order by its ID",
        responses={200: "Order Detail retrieved successfully", 404: "User not found.", 400: "Bad request."},
        tags=["Admin API"],
    )
    def retrieve(self, request, pk=None):
        """
        Retrieve a single order with its payment details.
        """
        try:
            # Ensure we only get orders with associated payments
            order = self.get_queryset().filter(orderproduct__payment__isnull=False).get(pk=pk)
            print('order: ', order)
        except Order.DoesNotExist:
            return CustomResponse.error(
                "Order not found.",
                status_code=status.HTTP_404_NOT_FOUND
            )

        serializer = self.serializer_class(order)
        return CustomResponse.success(
            message="Order Detail retrieved successfully.",
            data=serializer.data
        )


#<---------------------------Admin Order Detail ViewSets Starts From Here------------------------->
class AdminOrderDetailViewSet(viewsets.GenericViewSet):
    """
    A viewset for admin operations on orders.
    """
    queryset = Order.objects.all()
    serializer_class = userauths_serializer.AdminOrderDetailSerializer
    permission_classes = [IsSuperuser]              # Replace with your custom permission class if needed
    pagination_class = pagination.PageNumberPagination
    filter_backends = [
        DjangoFilterBackend,
        # filters.SearchFilter,
        filters.OrderingFilter,
    ]
    search_fields = [
        # "id",
        "first_name",
        "last_name",
        "phone_number",
        "order_id"
    ]
    ordering_fields = [
        # "id",
        "first_name",
        "last_name",
        "total_amount",
        "made_on",
    ]
    ordering = ['first_name']        # Default ordering



    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'first_name', openapi.IN_QUERY, 
                description="Filter by First Name", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'made_on', openapi.IN_QUERY, 
                description="Filter by Made On", 
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'order_id', openapi.IN_QUERY, 
                description="Filter by Order ID", 
                type=openapi.TYPE_STRING
            ),
        ],
        tags=["Admin API"],
        responses={
        200: "Orders List retrieved successfully.",
        400: "Bad request.",
        },
    )
    def list(self, request):
        """
        Lists all orders with their payment details.
        """
        queryset = self.get_queryset()

        # Apply filters if needed
        first_name = request.query_params.get("first_name", None)
        made_on = request.query_params.get("made_on", None)
        order_id = request.query_params.get("order_id", None)

        if first_name:
            queryset = queryset.filter(first_name__istartswith=first_name)
            print('==============queryset: ', queryset)

            # Check if no results are found after filtering by first_name
            if not queryset.exists():
                return CustomResponse.error(
                    f"No orders found for the first name starting with '{first_name}'.",
                    status_code=status.HTTP_404_NOT_FOUND
                )
            
        if made_on:
            try:
                # Convert the string input into a date object
                made_on_date = datetime.strptime(made_on, "%Y-%m-%d").date()
                print('>>>>>>>>>made_on_date: ', made_on_date)

                # Handle timezone-aware datetime filtering (if required)
                queryset = queryset.filter(orderproduct__payment__made_on__date=made_on_date)

                # If the queryset is empty after filtering by date, return a custom message
                if not queryset.exists():
                    return CustomResponse.error(
                        f"No orders found for the date {made_on_date}.",
                        status_code=status.HTTP_404_NOT_FOUND
                    )

            except ValueError:
                return CustomResponse.error(
                    "Invalid date format. Please enter a date in the correct format (YYYY-MM-DD).",
                    status_code=status.HTTP_400_BAD_REQUEST
                )

        if order_id:
            queryset = queryset.filter(orderproduct__payment__order_id=order_id)

            # Check if no results are found after filtering by order_id
            if not queryset.exists():
                return CustomResponse.error(
                    f"No orders found for the order ID '{order_id}'.",
                    status_code=status.HTTP_404_NOT_FOUND
                )

        # Ensure we only get orders with associated payments
        queryset = queryset.filter(orderproduct__payment__isnull=False)

        # Apply dynamic ordering
        ordering_param = request.query_params.get("ordering", None)

        if ordering_param:
            # Handle ascending or descending order based on the param
            if ordering_param == "a":  # Ascending order by username
                queryset = queryset.order_by("first_name")
            elif ordering_param == "z":  # Descending order by username
                queryset = queryset.order_by("-first_name")
            else:
                # Validate fields specified in the ordering param
                valid_ordering_fields = [field for field in ordering_param.split(",") if field.lstrip("-") in self.ordering_fields]
                if valid_ordering_fields:
                    queryset = queryset.order_by(*valid_ordering_fields)
                else:
                    # Fallback to default ordering if no valid fields
                    queryset = queryset.order_by(*self.ordering)
        else:
            # Default ordering
            queryset = queryset.order_by(*self.ordering)


        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)

        # Return success response with serialized data
        serializer = self.serializer_class(queryset, many=True)
        return CustomResponse.success(
            message="Orders List retrieved successfully.",
            data=serializer.data
        )

    @swagger_auto_schema(
        operation_description="Retrieve an order by its ID",
        responses={200: "Order Details retrieved successfully", 404: "User not found.", 400: "Bad request."},
        tags=["Admin API"],
    )
    def retrieve(self, request, pk=None):
        """
        Retrieve a single order with its payment details.
        """
        try:
            # Ensure we only get orders with associated payments
            order = self.get_queryset().filter(orderproduct__payment__isnull=False).get(pk=pk)
            print('order: ', order)
        except Order.DoesNotExist:
            return CustomResponse.error(
                "Order not found.",
                status_code=status.HTTP_404_NOT_FOUND
            )

        serializer = self.serializer_class(order)
        return CustomResponse.success(
            message="Order Details retrieved successfully.",
            data=serializer.data
        )

#<---------------------------Admin Category Views Starts From Here----------------------------->
class AdminCategoryListCreateView(generics.GenericAPIView):
    serializer_class = userauths_serializer.AdminCategorySerializer
    parser_classes = [MultiPartParser, FormParser]                  # Handle file uploads
    permission_classes = [IsSuperuser]
    queryset = Category.objects.all()
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['title']              # Enable filtering by category name
    ordering_fields = ['title']               # Enable ordering by 'id'
    ordering = ['title']                      # Default ordering
    pagination_class = pagination.PageNumberPagination


    @swagger_auto_schema(
        operation_description="List all categories",
        responses={
            200: "Categories List retrieved successfully",
            404: "No categories found",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def get(self, request, *args, **kwargs):
        # Start with the base queryset
        queryset = self.get_queryset()

        # Apply search filter for 'title'
        title = request.query_params.get("title", None)
        if title:
            queryset = queryset.filter(title__istartswith=title)

        # Apply dynamic ordering if the ordering param is provided
        ordering_param = request.query_params.get("ordering", None)
        print('>>>>>>>>>>ordering_param: ', ordering_param)

        # Validate and apply dynamic ordering
        if ordering_param:
            if ordering_param == 'a':
                # Ascending order by title
                queryset = queryset.order_by('title')
            elif ordering_param == 'z':
                # Descending order by title
                queryset = queryset.order_by('-title')
            else:
                # Check for valid ordering fields in the query params
                valid_ordering_fields = [field for field in ordering_param.split(',') if field in self.ordering_fields]
                if valid_ordering_fields:
                    queryset = queryset.order_by(*valid_ordering_fields)
                else:
                    # If no valid fields, fallback to default ordering
                    queryset = queryset.order_by(*self.ordering)


        # Check if any categories are found
        if not queryset.exists():
            return CustomResponse.error(
                message="No categories found.",
                status_code=status.HTTP_404_NOT_FOUND
            )

        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(
                CustomResponse.success(
                    message="Categories list retrieved successfully.",
                    data=serializer.data
                ).data
            )

        # Return success response with serialized data
        serializer = self.serializer_class(queryset, many=True)
        return CustomResponse.success(
            message="Categories list retrieved successfully.",
            data=serializer.data
        )


    @swagger_auto_schema(
        operation_description="Create a new Category with image upload",
        manual_parameters=[
            openapi.Parameter(
                name="title",
                in_=openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="Title of the category",
                required=True,
            ),
            openapi.Parameter(
                name="category_image",
                in_=openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                description="Image file for the category",
                required=True,
            ),
        ],
        responses={
            201: "Category created successfully",
            400: "Bad Request",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            category = serializer.save()
            return CustomResponse.success(
                message="Category created successfully.",
                data={
                    "id": category.id,
                    "title": category.title,
                    "category_image": request.build_absolute_uri(category.category_image.url)
                },
                status_code=status.HTTP_201_CREATED
            )
        return CustomResponse.error(
            message="Failed to create category",
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )

#<-------------------Admin Category Retrieve Update Delete View Starts From Here------------------>
class AdminCategoryRetrievUpdateDeleteView(generics.GenericAPIView):
    serializer_class = userauths_serializer.AdminCategorySerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsSuperuser]
    queryset = Category.objects.all()

    def get_object(self, pk):
        try:
            return self.queryset.get(pk=pk)
        except Category.DoesNotExist:
            return None
    
    @swagger_auto_schema(
        operation_description="Retrieve a specific category",
        responses={
            200: "Specific Category retrieved successfully",
            404: "Category not found",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def get(self, request, pk, *args, **kwargs):
        try:
            # Attempt to retrieve the category by its ID
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            # Return custom error response if category not found
            return CustomResponse.error(
                message="Category with the given ID does not exist.",
                data=None,
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        serializer = self.get_serializer(category)
        return CustomResponse.success(
            message="Specific Category retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        operation_description="Update a specific category",
        manual_parameters=[
            openapi.Parameter(
                name="title",
                in_=openapi.IN_FORM,
                type=openapi.TYPE_STRING,
                description="Title of the category",
                required=True,
            ),
            openapi.Parameter(
                name="category_image",
                in_=openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                description="Image file for the category (optional for update)",
                required=False,
            ),
        ],
        responses={
            200: "Category updated successfully",
            400: "Bad Request",
            404: "Category not found",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def put(self, request, pk, *args, **kwargs):
        try:
            # Retrieve the category instance by ID
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return CustomResponse.error(
                message="Category with the given ID does not exist.",
                data=None,
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        serializer = self.get_serializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return CustomResponse.success(
                message="Category Updated Successfully.",
                data=serializer.data,
                status_code=status.HTTP_200_OK
            )

        return CustomResponse.error(
            message="Failed to update category.",
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST
        )

    @swagger_auto_schema(
        operation_description="Delete a specific category",
        responses={
            200: "Category deleted successfully",
            404: "Category not found",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def delete(self, request, pk, *args, **kwargs):
        try:
            # Try to retrieve the category by its ID
            category = Category.objects.get(pk=pk)
            
            # Delete the category if found
            category.delete()
            return CustomResponse.success(
                message="Category deleted successfully.",
                status_code=status.HTTP_200_OK
            )
        
        except Category.DoesNotExist:
            # Handle the case where the category does not exist
            return CustomResponse.error(
                message="Category not found.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        except Exception as e:
            # Handle any unexpected errors
            return CustomResponse.error(
                message=f"An error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

#<---------------------------Admin Product API View Starts From Here---------------------------->
class AdminProductListCreateView(generics.GenericAPIView):
    serializer_class = userauths_serializer.AdminProductSerializer
    queryset = Product.objects.all()
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsSuperuser]

    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['title', 'category__title', 'brand']  # Corrected field names
    ordering_fields = ["title", "category__title", "brand"]   # Corrected field names
    ordering = ["category__title"]
    pagination_class = pagination.PageNumberPagination


    @swagger_auto_schema(
        operation_description="Retrieve a list of all products with optional search, ordering, and pagination.",
        responses={
            200: "Products retrieved successfully",
            404: "No Products found",
            500: "Internal Server Error",
        },
        tags=["Admin API"],
    )
    def get(self, request):
        try:
            # Retrieve query parameters
            title = request.query_params.get("title", None)
            category_name = request.query_params.get("category__title", None)
            brand = request.query_params.get("brand", None)

            # Filter products based on query parameters
            filters = Q()
            if title:
                filters &= Q(title__istartswith=title)
            if category_name:
                filters &= Q(category__title__istartswith=category_name)
            if brand:
                filters &= Q(brand__icontains=brand)

            queryset = Product.objects.filter(filters)

            # Apply dynamic ordering if the ordering param is provided
            ordering_param = request.query_params.get("ordering", None)
            print('>>>>>>>>>>ordering_param: ', ordering_param)

            # Validate and apply dynamic ordering
            if ordering_param:
                if ordering_param == 'a':
                # Ascending order by title
                    queryset = queryset.order_by('title')
                elif ordering_param == 'z':
                    # Descending order by title
                    queryset = queryset.order_by('-title')
                else:
                    # Check for valid ordering fields in the query params
                    valid_ordering_fields = [field for field in ordering_param.split(',') if field in self.ordering_fields]
                    if valid_ordering_fields:
                        queryset = queryset.order_by(*valid_ordering_fields)
                    else:
                        # If no valid fields, fallback to default ordering
                        queryset = queryset.order_by(*self.ordering)


            # Apply pagination
            paginator = pagination.PageNumberPagination()
            page = paginator.paginate_queryset(queryset, request)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return paginator.get_paginated_response(
                    CustomResponse.success(
                        message="Products retrieved successfully.",
                        data=serializer.data,
                    ).data
                )

            # Serialize without pagination (fallback)
            serializer = self.serializer_class(queryset, many=True)
            return CustomResponse.success(
                message="Products retrieved successfully.",
                data=serializer.data,
            )

        except Exception as e:
            return CustomResponse.error(
                message=f"An error occurred: {str(e)}",
                data=None,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    

    @swagger_auto_schema(
        operation_description="This endpoint allows creating a new product.",
        manual_parameters=[
            openapi.Parameter(
                "title", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Title of the product", required=True
            ),
            openapi.Parameter(
                "selling_price", openapi.IN_FORM, type=openapi.TYPE_NUMBER, description="Selling price of the product", required=True
            ),
            openapi.Parameter(
                "discounted_price", openapi.IN_FORM, type=openapi.TYPE_NUMBER, description="Discounted price of the product", required=True
            ),
            openapi.Parameter(
                "description", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Description of the product", required=True
            ),
            openapi.Parameter(
                "brand", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Brand of the product", required=True
            ),
            openapi.Parameter(
                "product_image", openapi.IN_FORM, type=openapi.TYPE_FILE, description="Image of the product", required=True
            ),
            openapi.Parameter(
                "user", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Username of the user creating the product", required=True
            ),
            openapi.Parameter(
                "category", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Category title of the product", required=True
            ),
        ],
        responses={
            201: "Product created successfully",
            400: "Bad Request",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def post(self, request):
        serializer = userauths_serializer.AdminProductSerializer(data=request.data)
        if serializer.is_valid():
            try:
                # Validate and assign User
                if "user" in request.data:
                    username = request.data["user"]
                    try:
                        user = User.objects.get(username=username)
                        serializer.validated_data["user"] = user
                    except User.DoesNotExist:
                        return CustomResponse.error(
                            message="User matching the given username does not exist.",
                            data=None,
                            # status_code=status.HTTP_400_BAD_REQUEST
                        )
                
                # Validate and assign Category
                if "category" in request.data:
                    category_title = request.data["category"]
                    try:
                        category = Category.objects.get(title=category_title)
                        serializer.validated_data["category"] = category
                    except Category.DoesNotExist:
                        return CustomResponse.error(
                            message="Category matching the given title does not exist.",
                            data=None,
                            # status_code=status.HTTP_400_BAD_REQUEST
                        )
                
                # Save product
                serializer.save()
                return CustomResponse.success(
                    message="Product created successfully.",
                    data=serializer.data,
                    status_code=status.HTTP_201_CREATED
                )
            except Exception as e:
                return CustomResponse.error(
                    message=f"An unexpected error occurred: {str(e)}",
                    data=None,
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return CustomResponse.error(
                message="Invalid input data.",
                data=serializer.errors,
                # status_code=status.HTTP_400_BAD_REQUEST
            )
    


#<----------------------Admin Product Retrieve Update Delete View API Starts From Here------------->
class AdminProductRetrieveUpdateDeletelView(APIView):
    serializer_class = userauths_serializer.AdminProductSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsSuperuser]

    def get_object(self, pk):
        try:
            return Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_description="Retrieve a specific product by its ID.",
        responses={
            200: "Products retrieved successfully.",
            400: "Product not found"
        },
        tags=["Admin API"],
    )
    def get(self, request, pk):
        try:
            # Retrieve the product instance by ID
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            # Return custom error response if product is not found
            return CustomResponse.error(
                message="Product with the given ID does not exist.",
                data=None,
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        serializer = userauths_serializer.AdminProductSerializer(product)
        return CustomResponse.success(
            message="Products retrieved successfully.",
            data=serializer.data,
            # status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        operation_description="Update a specific product by its ID.",
        manual_parameters=[
            openapi.Parameter(
                "title", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Title of the product", required=False
            ),
            openapi.Parameter(
                "selling_price", openapi.IN_FORM, type=openapi.TYPE_NUMBER, description="Selling price of the product", required=False
            ),
            openapi.Parameter(
                "discounted_price", openapi.IN_FORM, type=openapi.TYPE_NUMBER, description="Discounted price of the product", required=False
            ),
            openapi.Parameter(
                "description", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Description of the product", required=False
            ),
            openapi.Parameter(
                "brand", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Brand of the product", required=False
            ),
            openapi.Parameter(
                "product_image", openapi.IN_FORM, type=openapi.TYPE_FILE, description="Image of the product", required=False
            ),
            openapi.Parameter(
                "user", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Username of the user associated with the product", required=False
            ),
            openapi.Parameter(
                "category", openapi.IN_FORM, type=openapi.TYPE_STRING, description="Category of the product", required=False
            ),
        ],
        responses={
            201: "Product created successfully",
            400: "Bad Request",
            404: "Product, User, or Category not found",
            500: "Internal Server Error"
        },
        tags=["Admin API"],
    )
    def put(self, request, pk):
        try:
            # Retrieve the product instance by ID
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return CustomResponse.error(
                message="Product with the given ID does not exist.",
                data=None,
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        serializer = userauths_serializer.AdminProductSerializer(product, data=request.data)
        if serializer.is_valid():
            try:
                # Validate User and Category fields if provided
                if "user" in request.data:
                    username = request.data["user"]
                    user = User.objects.get(username=username)
                    serializer.validated_data["user"] = user

                if "category" in request.data:
                    category_title = request.data["category"]
                    category = Category.objects.get(title=category_title)
                    serializer.validated_data["category"] = category

                # Save the product
                serializer.save()
                return CustomResponse.success(
                    message="Product updated successfully.",
                    data=serializer.data,
                    # status_code=status.HTTP_200_OK
                )
            except User.DoesNotExist:
                return CustomResponse.error(
                    message="User matching the given username does not exist.",
                    data=None,
                    # status_code=status.HTTP_400_BAD_REQUEST
                )
            except Category.DoesNotExist:
                return CustomResponse.error(
                    message="Category matching the given title does not exist.",
                    data=None,
                    # status_code=status.HTTP_400_BAD_REQUEST
            )
        else:
            return CustomResponse.error(
                message="Invalid input data.",
                data=serializer.errors,
                # status_code=status.HTTP_400_BAD_REQUEST
            )



    @swagger_auto_schema(
        operation_description="Delete a specific product by its ID.",
        responses={
            204: "Product deleted successfully",
            404: "Product not found"
        },
        tags=["Admin API"],
    )
    def delete(self, request, pk):
        try:
            # Attempt to retrieve the product by its ID
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            # Return custom error response if product not found
            return CustomResponse.error(
                message="Product with the given ID does not exist.",
                data=None,
                status_code=status.HTTP_404_NOT_FOUND
            )
        
        except Exception as e:
            # Handle any unexpected errors
            return CustomResponse.error(
                message=f"An error occurred: {str(e)}",
                data=None,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Delete the product if it exists
        product.delete()
        return CustomResponse.success(
            message="Product deleted successfully.",
            data=None,
            status_code=status.HTTP_200_OK
        )