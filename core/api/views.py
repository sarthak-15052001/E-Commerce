import uuid

import stripe
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.db import connection
from django.db.models import Prefetch
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import get_template
from django.views import View
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import filters, generics, serializers, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.views import TokenRefreshView
from xhtml2pdf import pisa

from core import models as core_models
from core.api import serializers as core_serializer
from core.api.forms import ResetPasswordForm
from E_Commerce_Website import settings
from E_Commerce_Website.app_helpers import CustomResponse
from userauths import models as user_models
from userauths.api import pagination

stripe.api_key = settings.STRIPE_SECRET_KEY
endpoint_secret = settings.STRIPE_WEBHOOK_SECRET_KEY


class SignupView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = core_serializer.SignupSerializer

    @swagger_auto_schema(
        operation_description="User signup endpoint",
        responses={201: "User created successfully", 400: "Bad request"},
        tags=["User API"],
    )
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)

            if serializer.is_valid(raise_exception=True):
                super().post(request, *args, **kwargs)
                return CustomResponse.success(
                    message="Email verification link sent on your email id."
                )

        except serializers.ValidationError as e:
            email_error = e.detail.get("email", [None])[0]
            if email_error:
                return CustomResponse.error(message=email_error)

            role_error = e.detail.get("role", [None])[0]

            if role_error:
                return CustomResponse.error(message=role_error)

            error_messages = []
            for field, messages in e.detail.items():
                if isinstance(messages, list):
                    error_messages.extend(messages)
                else:
                    error_messages.append(messages)
            return CustomResponse.error(
                message=error_messages[1] if error_messages else "Validation error."
            )


class LoginAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.LoginSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description=(
            "Endpoint for email-based login. "
            "Accepts email and password, validates the user credentials, and returns user details upon successful login."
        ),
        responses={
            200: "Login successful.",
            400: "Validation errors or incorrect login credentials.",
        },
        tags=["Token API"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid():
                user_data = serializer.validated_data
                return CustomResponse.success(
                    message="Logged in successfully.",
                    data=user_data,
                )
            return CustomResponse.error(
                message=next(iter(serializer.errors.values()))[0]
            )
        except serializers.ValidationError as e:
            error_messages = [
                msg
                for messages in e.detail.values()
                for msg in (messages if isinstance(messages, list) else [messages])
            ]
            return CustomResponse.error(
                message=error_messages[0] if error_messages else "Validation error."
            )


class VerifyEmailView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="User Email Verification",
        responses={404: "Token not found", 200: "Email verified successfully"},
        tags=["User API"],
    )
    def get(self, request, token, *args, **kwargs):
        try:
            user = user_models.User.objects.filter(email_token=token).first()

            if not user:
                # Render HTML for token not found
                return render(
                    request,
                    "api/token_not_found.html",
                    {"error": "Token not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Check if the user is already verified
            if user.email_verified:
                return render(
                    request,
                    "api/email_verified.html",
                    {"message": "Email already verified!"},
                )

            # Set email as verified and save the user
            user.email_verified = True
            user.save()

            return render(
                request,
                "api/email_verified.html",
                {"message": "Email verified successfully!"},
            )

        except Exception:
            return CustomResponse.error(
                message="Server error",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CustomTokenRefreshView(TokenRefreshView):
    @swagger_auto_schema(
        description="Endpoint to refresh an access token using a valid refresh token.",
        responses={
            200: "Access token generated",
            400: "An error occurred while refreshing the token.",
        },  # No custom request body needed, the default is fine
        tags=["Token API"],
    )
    def post(self, request, *args, **kwargs):
        # Call the parent class's post method to get the original response
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            return CustomResponse.success(
                message="Access token generated",
                data={"access_token": response.data.get("access")},
            )

        return CustomResponse


class ForgotPasswordAPIView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = core_serializer.ForgotPasswordSerializer

    @swagger_auto_schema(
        operation_description="partial_update description override",
        responses={404: "slug not found", 200: "not found"},
        tags=["User API"],
    )
    def post(self, request, *args, **kwargs):
        try:
            # Validate the request data
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data["email"]

            try:
                user = user_models.User.objects.get(email=email)
                if not user.email_verified:
                    return CustomResponse.error(
                        message="Please verify your email first, and then proceed with reset your password.",
                    )
            except user_models.User.DoesNotExist:
                return Response(
                    {"detail": "User with this email does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Generate a unique email token and save it
            user.email_token = str(uuid.uuid4())
            user.save()

            # Construct the password reset link
            reset_link = f"{settings.USER_BASE_URL}reset-password/{user.email_token}"

            # Send the reset password email
            subject = "Password Reset Request"
            message = f"Hi {user.first_name},\n\nPlease click the link below to reset your password:\n{reset_link}\n\nIf you did not request this, please ignore this email."
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.email]
            send_mail(subject, message, email_from, recipient_list)

            return CustomResponse.success(
                message="Password reset link sent to your email.",
            )

        except serializers.ValidationError:
            return CustomResponse.error(
                message="Invalid email format",
            )

        except Exception as e:
            return CustomResponse.error(
                message=str(e),
            )


class ResetPasswordView(View):
    def get(self, request, token=None):
        form = ResetPasswordForm()
        return render(
            request, "api/reset_password.html", {"form": form, "token": token}
        )

    def post(self, request, token=None):
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data["password"]
            try:
                user = user_models.User.objects.get(email_token=token)
                user.password = make_password(password)
                user.email_token = None
                user.save()
                return HttpResponse("Password has been reset successfully.")
            except user_models.User.DoesNotExist:
                messages.error(request, "Invalid token or user does not exist.")

        return render(
            request, "api/reset_password.html", {"form": form, "token": token}
        )


class ChangePassword(generics.GenericAPIView):
    serializer_class = core_serializer.ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description=(
            "Endpoint to reset the user's password. "
            "The user must provide the Current password and a new password. "
            "This endpoint is not applicable for social users."
        ),
        responses={
            200: "Password successfully updated.",
            400: "Password doesn't match.",
        },
        tags=["User API"],
    )
    def post(self, request, *args, **kwargs):
        try:
            user = request.user
            serializer = self.get_serializer(data=request.data, context={"user": user})

            serializer.is_valid(raise_exception=True)

            user.set_password(serializer.validated_data["new_password"])
            user.save()
            return CustomResponse.success(message="Password Changed Successfully.")

            error_message = next(iter(serializer.errors.values()))[0]
            return CustomResponse.error(message=error_message)
        except serializers.ValidationError as e:  # Handle validation errors
            error_messages = []
            for field, messages in e.detail.items():
                if isinstance(messages, list):
                    error_messages.extend(messages)
                else:
                    error_messages.append(messages)
            return CustomResponse.error(
                message=error_messages[0] if error_messages else "Validation error."
            )


class SignoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = core_serializer.SignoutSerializer

    @swagger_auto_schema(
        operation_description="Log out the user by blacklisting their refresh token.",
        request_body=core_serializer.SignoutSerializer,
        responses={
            200: "User logged out successfully.",
            400: "Refresh token missing or invalid token.",
        },
        tags=["User API"],
    )
    def post(self, request, *args, **kwargs):
        """
        Log out the user by blacklisting their refresh token.
        """
        try:
            user = request.user
            # Get the refresh token from the request data
            access_token = request.data.get("access_token")

            if access_token:
                # Validate the token
                token = AccessToken(access_token)
                # Save the token in the SQLite database
                user_models.BlacklistedToken.objects.create(token=str(token))

                # user.device = None
                user.save()

                return CustomResponse.success(message="Logged out successfully.")
            else:
                return CustomResponse.error(message="Access token missing.")
        except Exception:
            return CustomResponse.error(message="Invalid token or token expired.")


class CustomerProfileAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.UserProfileSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Endpoint to retrieve the details of the currently logged-in user.",
        responses={
            200: "User details retrieved successfully.",
            404: "User not found.",
        },
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        try:
            # Get the authenticated user
            user = request.user

            # Try to fetch the user profile
            profile = user_models.UserProfile.objects.get(user=user)

            # Serialize and return the profile data
            serializer = self.get_serializer(profile)
            return CustomResponse.success(
                message="User profile fetched successfully.",
                data=serializer.data,
            )

        except user_models.UserProfile.DoesNotExist:
            return CustomResponse.error(
                message="User profile not found.",
            )


class CustomerProfileUpdateAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.UserUpdateProfileSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get_object(self, user):
        """
        Retrieve UserProfile object for the logged-in user.
        """
        try:
            return user_models.UserProfile.objects.get(user=user)
        except user_models.UserProfile.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_description="Update the logged-in customer's profile.",
        responses={
            200: "Profile updated successfully.",
            400: "Bad request. Invalid input.",
            404: "Profile not found.",
        },
        tags=["User API"],
    )
    def put(self, request, *args, **kwargs):
        """
        Update the logged-in user's profile.
        """
        user_profile = self.get_object(request.user)
        if not user_profile:
            return CustomResponse.error(
                message="Profile not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer = self.get_serializer(user_profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return CustomResponse.success(
                message="Profile updated successfully.",
                data=serializer.data,
                status_code=status.HTTP_200_OK,
            )

        return CustomResponse.error(
            message="Invalid data provided.",
            data=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CustomerUserDasboardAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Dashboard data Verification",
        responses={400: "Bad Request", 200: "Dashboard data fetched successfully."},
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        user = request.user

        total_orders = core_models.Order.objects.filter(user=user).count()

        data = {
            "total_orders": total_orders,
        }
        return CustomResponse.success(
            message="Dashboard data fetched successfully.", data=data
        )


class CustomerOrderHistoryAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = core_serializer.CustomerOrderListSerializer

    @swagger_auto_schema(
        operation_description="Customers order list endpoint",
        responses={
            200: "Customer order list fetched successfully.",
            400: "Bad Request",
        },
        tags=["User API"],
    )
    def get(self, request):
        user = self.request.user
        orders = core_models.Payment.objects.filter(user=user).order_by(
            "-id"
        )  # latest orders first
        serializer = self.serializer_class(orders, many=True)
        return CustomResponse.success(
            message="Customer order list fetched successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )


class CustomerInvoiceDetailAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = core_serializer.CustomerOrderDetailSerializer

    def get_object(self, user):
        payment_id = self.kwargs.get("id")
        if not payment_id:
            return None, CustomResponse.error(
                message="Invoice ID cannot be empty.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        try:
            payment = core_models.Payment.objects.get(id=payment_id)
        except core_models.Payment.DoesNotExist:
            return None, CustomResponse.error(
                message="Invoice not found.", status_code=status.HTTP_404_NOT_FOUND
            )

        # Check that the invoice belongs to the logged-in user
        if payment.user != user:
            return None, CustomResponse.error(
                message="Invoice not found.", status_code=status.HTTP_403_FORBIDDEN
            )
        return payment, None

    @swagger_auto_schema(
        operation_description="Customers order detail endpoint",
        responses={
            200: "Customer order detail fetched successfully.",
            400: "Bad Request",
        },
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        payment, error_response = self.get_object(request.user)
        if error_response:
            return error_response

        serializer = self.get_serializer(payment)
        return CustomResponse.success(
            message="Invoice retrieved successfully",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )


class HomeAPIView(generics.GenericAPIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = core_serializer.CategoryWithProductAndReviewSerializer

    @swagger_auto_schema(
        operation_description="Home List endpoint",
        responses={
            200: "Home List fetched successfully.",
            400: "Bad Request",
        },
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        # Prefetch products with randomized order
        categories = core_models.Category.objects.prefetch_related(
            Prefetch("product_set", queryset=core_models.Product.objects.order_by("?"))
        )

        # Attach approved reviews manually to each product
        for category in categories:
            for product in category.product_set.all():
                product.reviews = core_models.ReviewRating.objects.filter(
                    product=product, status=True
                )

        # Print SQL queries for debug
        print(connection.queries)

        serializer = self.get_serializer(categories, many=True)
        return CustomResponse.success(
            message="Home List fetched successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )


class StoreAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.ProductFullSerializer
    queryset = core_models.Product.objects.all()
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    pagination_class = pagination.UserPagination

    search_fields = [
        "category__title",
        "brand",
    ]
    ordering_fields = [
        "title",
        "selling_price",
        "discounted_price",
        "brand",
    ]
    ordering = ["id"]
    category_title_param = openapi.Parameter(
        "category",
        openapi.IN_QUERY,
        description="Category title",
        type=openapi.TYPE_STRING,
    )
    brand_title_param = openapi.Parameter(
        "brand",
        openapi.IN_QUERY,
        description="Brand name (e.g., Nike, Adidas)",
        type=openapi.TYPE_STRING,
    )
    min_price_param = openapi.Parameter(
        "min_price",
        openapi.IN_QUERY,
        description="Minimum selling price",
        type=openapi.TYPE_NUMBER,
        format=openapi.FORMAT_FLOAT,
    )
    max_price_param = openapi.Parameter(
        "max_price",
        openapi.IN_QUERY,
        description="Maximum selling price",
        type=openapi.TYPE_NUMBER,
        format=openapi.FORMAT_FLOAT,
    )

    @swagger_auto_schema(
        manual_parameters=[
            category_title_param,
            brand_title_param,
            min_price_param,
            max_price_param,
        ],
        operation_description="Store List endpoint with filters: category, brand, min_price, max_price, plus search, ordering, and pagination.",
        responses={
            200: "Store List fetched successfully.",
            400: "Bad Request",
        },
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        try:
            queryset = self.get_filtered_queryset()

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(
                    page, many=True, context={"request": request}
                )
                paginated_data = self.get_paginated_response(serializer.data).data
            else:
                serializer = self.get_serializer(
                    queryset, many=True, context={"request": request}
                )
                paginated_data = serializer.data

            category = request.GET.get("category")
            if category:
                brands = (
                    core_models.Product.objects.filter(category__title__iexact=category)
                    .values_list("brand", flat=True)
                    .distinct()
                )
            else:
                brands = core_models.Product.objects.values_list(
                    "brand", flat=True
                ).distinct()

            return CustomResponse.success(
                data={
                    "products": paginated_data,
                    "brands": list(brands),
                },
                message="Store list fetched successfully",
            )

        except Exception as e:
            return CustomResponse.error(str(e))

    def get_filtered_queryset(self):
        queryset = self.filter_queryset(self.get_queryset())

        request = self.request
        category = request.GET.get("category")
        brand = request.GET.get("brand")
        min_price = request.GET.get("min_price")
        max_price = request.GET.get("max_price")

        if category:
            queryset = queryset.filter(category__title__iexact=category)

        if brand and brand.lower() != "all":
            queryset = queryset.filter(brand__iexact=brand)

        if min_price:
            queryset = queryset.filter(selling_price__gte=min_price)

        if max_price:
            queryset = queryset.filter(selling_price__lte=max_price)

        return queryset


class ProductDetailAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.ProductDetailSerializer
    queryset = core_models.Product.objects.all()

    def get_object(self, pk):
        try:
            return self.queryset.get(pk=pk)
        except core_models.Product.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_description="Product Details Endpoint.",
        responses={
            200: "Product Details fetched successfully.",
            400: "Bad Request",
        },
        tags=["User API"],
    )
    def get(self, request, pk, *args, **kwargs):
        product = self.get_object(pk)
        if not product:
            return CustomResponse.error(
                "Product not found", status_code=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(product, context={"request": request})
        total_reviews = core_models.ReviewRating.objects.filter(
            product=product, status=True
        ).count()

        return CustomResponse.success(
            data={"product": serializer.data, "total_reviews": total_reviews},
            message="Product details fetched successfully",
        )


class AddToCartAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.AddToCartSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Add Product to Cart",
        responses={
            200: "Product added to cart successfully.",
            400: "Bad Request",
        },
        tags=["User API"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            product = serializer.validated_data["product"]
            quantity = serializer.validated_data.get("quantity", 1)

            cart, created = core_models.Cart.objects.get_or_create(
                user=request.user, product=product
            )
            if not created:
                cart.quantity += quantity
            else:
                cart.quantity = quantity
            cart.save()
            return CustomResponse.success(
                message="Product added to cart successfully.",
                data={
                    "cart_id": cart.id,
                    "product": product.title,
                    "user": request.user.first_name,
                    "quantity": cart.quantity,
                },
            )
        return CustomResponse.error(
            message="Invalid data provided.", status_code=status.HTTP_404_NOT_FOUND
        )


class CartDetailAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.CartItemSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all cart items with product details",
        responses={200: "Cart fetched successfully", 400: "Bad request"},
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        user = request.user
        cart_items = core_models.Cart.objects.filter(user=user)

        if not cart_items.exists():
            return CustomResponse.error(
                message="Your cart is empty.", status_code=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(cart_items, many=True)
        cart_data = serializer.data

        shipping_amount = 70.0
        cart_total = sum(item["total_price"] for item in cart_data)
        final_total = cart_total + shipping_amount if cart_data else 0.0

        return CustomResponse.success(
            message="Cart fetched successfully.",
            data={
                "cart_items": cart_data,
                "cart_total_amount": cart_total,
                "shipping_amount": shipping_amount if cart_data else 0.0,
                "final_total_amount": final_total,
            },
        )


class RemoveFromCartAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get_object(self):
        cart_id = self.kwargs.get("id")
        user = self.request.user

        if not cart_id:
            return None, CustomResponse.error(message="Cart ID is required.")

        try:
            cart_item = core_models.Cart.objects.get(id=cart_id, user=user)
            return cart_item, None
        except core_models.Cart.DoesNotExist:
            return None, CustomResponse.error(
                message="Cart item not found.", status_code=status.HTTP_404_NOT_FOUND
            )

    @swagger_auto_schema(
        operation_description="Remove cart item using cart_id",
        responses={
            200: "Cart item removed successfully.",
            404: "Bad Request or cart item not found.",
        },
        tags=["User API"],
    )
    def delete(self, request, *args, **kwargs):
        cart_item, error_response = self.get_object()
        if error_response:
            return error_response

        cart_item.delete()
        return CustomResponse.success(
            message="Cart item removed successfully.",
        )


class CheckoutAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.CheckoutSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    @swagger_auto_schema(
        operation_description="Checkout API",
        responses={
            201: "Order placed successfully.",
            400: "Validation error or missing fields.",
        },
        tags=["User API"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        oder = serializer.save()
        return CustomResponse.success(
            message="Checkout Successful.", status_code=status.HTTP_201_CREATED
        )


class CheckoutListAPIView(generics.ListAPIView):
    serializer_class = core_serializer.CheckoutSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return core_models.Order.objects.filter(user=self.request.user)

    @swagger_auto_schema(
        operation_description="Get list of checkout orders for the logged-in user",
        responses={200: "List of checkout orders retrieved successfully"},
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class PaymentAPIView(generics.GenericAPIView):
    serializer_class = core_serializer.PaymentSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    queryset = core_models.Payment.objects.none()

    @swagger_auto_schema(
        operation_description="Make payment using Cash or Card (Stripe).",
        responses={200: "Stripe URL / Cash Payment Success", 400: "Validation error"},
        tags=["User API"],
    )
    def post(self, request, pk, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        payment_type = serializer.validated_data["payment_type"]
        user = request.user
        order_product = get_object_or_404(core_models.OrderProduct, pk=pk)

        if payment_type == "Cash":
            # Create payment directly
            payment = core_models.Payment.objects.create(
                payment_type="Cash",
                user=user,
                orderproduct=order_product,
                total_amount=order_product.total_amount,
                payment_status="Paid",
            )
            return CustomResponse.success(
                message="Payment successful using Cash.",
                data={"payment_id": payment.id},
                status_code=status.HTTP_201_CREATED,
            )

        elif payment_type == "Card":
            # Create Stripe Checkout Session
            total_amount = int(order_product.total_amount * 100)  # in paise

            checkout_session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                line_items=[
                    {
                        "price_data": {
                            "currency": "inr",
                            "unit_amount": total_amount,
                            "product_data": {
                                "name": order_product.id,
                            },
                        },
                        "quantity": 1,
                    }
                ],
                mode="payment",
                success_url=f"{request.scheme}://{request.get_host()}/paymentsuccess/",
                cancel_url=f"{request.scheme}://{request.get_host()}/paymentcancel/",
                metadata={
                    "order_product_id": str(order_product.id),
                    "user_id": str(user.id),
                },
            )
            return CustomResponse.success(
                message="Stripe session created. Redirect to URL.",
                data={"checkout_url": checkout_session.url},
                status_code=status.HTTP_200_OK,
            )

        return CustomResponse.error(
            message="Invalid payment type.", status_code=status.HTTP_400_BAD_REQUEST
        )


class InvoiceDownloadAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Download invoice as PDF.",
        responses={
            200: "Invoice PDF Download.",
            400: "Bad Request",
            403: "Forbidden - You don't own this invoice",
            404: "Invoice not found",
        },
        tags=["User API"],
    )
    def get(self, request, *args, **kwargs):
        user = self.request.user
        payment_id = self.kwargs.get("id")

        if not payment_id:
            return HttpResponse("Invoice ID is required", status=400)

        try:
            # Only fetch the invoice if it belongs to the current user
            payment = core_models.Payment.objects.select_related(
                "orderproduct__Order", "orderproduct__product"
            ).get(id=payment_id, user=user)
        except core_models.Payment.DoesNotExist:
            return CustomResponse.error(
                message="Invoice not found or not accessible",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Fetch all order products related to the Order (not just one)
        order_products = core_models.OrderProduct.objects.filter(
            Order=payment.orderproduct.Order
        )

        context = {"payments": [payment], "order_products": order_products}

        # Load template and generate PDF
        template = get_template("pdf/invoice.html")
        html = template.render(context)
        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = (
            f'attachment; filename="invoice_{payment_id}.pdf"'
        )

        pisa_status = pisa.CreatePDF(html, dest=response)

        if pisa_status.err:
            return HttpResponse("Error generating PDF", status=500)

        return response
