from django.contrib import messages
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, serializers, status, viewsets, filters
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg import openapi
from E_Commerce_Website.app_helpers import CustomResponse
# from userauths.api import serializers as userauths_serializer
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
from core.api import serializers as users_serializer
from userauths.api import serializers as userauths_serializer
from django.core.exceptions import ObjectDoesNotExist




#<-------------User API Starts From Here----------------->

#<-------------------------------User Dashboard API Starts From Here-------------------------------->
# In this I have used no serializer

class UserDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Dashboard data verification",
        responses={
            200: "Dashboard data fetched successfully.",
            400: "Bad request",
            401: "Unauthorized access",
            404: "No dashboard data available.",
        },
        tags=["User API"],
    )
    def get(self, request):
        user = request.user                  # retrieves the currently authenticated user making the request.

        try:
            # Ensure the user is not a superuser
            # if user.is_superuser:                   # Checks if the currently authenticated user has superuser privileges.
            #     return CustomResponse.error(
            #         message="Superusers are not allowed to access this endpoint.",
            #         data=None,
            #         status_code=status.HTTP_403_FORBIDDEN
            #     )

            # Fetch user profile
            try:
                user_profile = UserProfile.objects.get(user=user)   # Attempts to retrieve the UserProfile associated with the authenticated user (user).
            except UserProfile.DoesNotExist:                       # If no UserProfile exists for the user, a UserProfile.DoesNotExist exception is raised
                user_profile = None                                # The exception is caught, and user_profile is set to None.

            # Fetch email and phone number from User model
            email = user.email                                    # Retrieves the user's email address from the User model.
            phone_number = getattr(user, 'phone_number', None)    # Uses getattr to safely fetch the phone_number attribute of the user object. If the phone_number attribute doesn’t exist, it returns None instead of raising an error.

            # Fetch total orders
            total_orders = Order.objects.filter(user=user).count()     # Queries the Order model for all records where the user field matches the authenticated user.

            # Check if all dashboard data is missing
            if not user_profile and not total_orders:                  # Checks if both user_profile and total_orders are missing (i.e., None or 0).
                return CustomResponse.error(                            # If true, it means there’s no data available to show for the user.
                    message="No dashboard data available for the user.",
                    data=None,
                    status_code=status.HTTP_404_NOT_FOUND
                )

            # Prepare response data
            data = {                       # Constructs a dictionary named data with the following keys:
                'email': email,
                'phone_number': phone_number,
                'profile_picture': user_profile.profile_picture.url if user_profile and user_profile.profile_picture else None,   # Checks if user_profile exists and has a valid profile_picture attribute. If so, fetches its URL (user_profile.profile_picture.url). Otherwise, sets profile_picture to None
                'total_orders': total_orders,
            }

            # Return a custom success response
            return CustomResponse.success(
                message="Dashboard data fetched successfully.",
                data=data
            )

        except Exception as e:
            # Return a custom error response
            return CustomResponse.error(
                message=f"An error occurred: {str(e)}",
                data=None,
                status_code=status.HTTP_400_BAD_REQUEST
            )

#<----------------------My Order List API View Starts From Here------------------------>
class UserOrderListAPIView(generics.GenericAPIView):
    """
    A view for listing all admin orders without any filters.
    """
    queryset = Order.objects.all()   # Specifies the default queryset for this view: all Order objects in the database.
    serializer_class = userauths_serializer.AdminOrderSerializer
    permission_classes = [IsAuthenticated]  # Ensure the user is logged in

    @swagger_auto_schema(
        responses={
            200: "Orders List retrieved successfully.",
            404: "No orders found for the user.",
            400: "Bad request.",
        },
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        """
        Handles GET requests to list orders for the logged-in user.
        """
        # Filter orders for the logged-in user
        queryset = self.get_queryset().filter(user=request.user, orderproduct__payment__isnull=False)


        if not queryset.exists():            # Checks if there are any matching orders after the filters are applied. Returns False if the queryset is empty.
            # Return message if no orders found for the user
            return CustomResponse.error(
                message="No orders found for the user.",
                status_code=status.HTTP_404_NOT_FOUND
            )
        

        # Serialize and return the response
        serializer = self.serializer_class(queryset, many=True)         # many=True: Indicates that multiple objects (a list of orders) will be serialized.


        return CustomResponse.success(
            message="Orders List retrieved successfully.",
            data=serializer.data
        )


'''
==> self.get_queryset(): Returns the queryset defined in the class (Order.objects.all()).
==> .filter(user=request.user): Filters orders to include only those belonging to the currently authenticated user.
==> orderproduct__payment__isnull=False:
==> Applies an additional filter: only include orders where payment related to the orderproduct is not null (i.e., payment exists).
'''

#<----------------------------User Order Details API View Starts From Here----------------------->
class UserOrderDetailAPIView(generics.GenericAPIView):
    """
    A view for retrieving logged-in user's order details.
    """
    serializer_class = userauths_serializer.AdminOrderDetailSerializer
    permission_classes = [IsAuthenticated]  # Ensures only authenticated users can access this endpoint

    @swagger_auto_schema(
        operation_description="Details Of Order",
        responses={
            200: "Order Details retrieved successfully.",
            404: "No orders found for the user.",
            400: "Bad request.",
        },
        tags=["User API"],  # Group under 'User API'
    )
    def get_queryset(self):
        """
        Retrieve orders associated with the logged-in user.
        """
        return Order.objects.filter(user=self.request.user)    # Queries the Order model to fetch orders where the user field matches the authenticated user making the request.

    def get(self, request, *args, **kwargs):
        """
        List all orders for the logged-in user.
        """
        queryset = self.get_queryset()                    # Calls the get_queryset method to retrieve orders for the logged-in user.

        # Ensure only orders with associated payments are retrieved
        queryset = queryset.filter(orderproduct__payment__isnull=False)

        if not queryset.exists():           # Checks if any records exist in the filtered queryset. 
            # Return message if no orders found for the user
            return CustomResponse.error(
                message="No orders found for the user.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Serialize the filtered queryset
        serializer = self.serializer_class(queryset, many=True)
        return CustomResponse.success(
            message="Orders List retrieved successfully.",
            data=serializer.data,
        )

    

#<-----------------------------User Profile Details API View Starts From Here---------------------->
