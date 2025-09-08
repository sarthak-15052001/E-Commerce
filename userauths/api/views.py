from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from rest_framework import filters, generics, status, viewsets
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from core import models as core_models
from E_Commerce_Website.app_helpers import CustomResponse
from E_Commerce_Website.permissions import IsSuperuser
from userauths import models as user_models
from userauths.api import pagination
from userauths.api import serializers as user_serializer


# <-------------------------Admin Profile Views Starts From Here------------------------------>
class AdminProfileView(generics.GenericAPIView):
    serializer_class = user_serializer.AdminProfileSerializer
    permission_classes = [IsSuperuser]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        operation_description="Admin profile endpoint",
        responses={200: "Profile retrieve successfully.", 400: "User not found"},
        tags=["Admin API"],
    )
    def get(self, request, *args, **kwargs):
        # Fetch only profiles associated with superusers
        profile = user_models.UserProfile.objects.select_related("user").filter(
            user__is_superuser=True
        )

        if profile.exists():
            serializer = self.get_serializer(profile, many=True)
            return CustomResponse.success(
                message="Profiles retrieved successfully.", data=serializer.data
            )
        return CustomResponse.error(message="No profiles found.")

    @swagger_auto_schema(
        operation_description="Admin update profile endpoint",
        request_body=user_serializer.AdminProfileSerializer,
        responses={200: "Profile updated successfully.", 400: "Invalid data provided."},
        tags=["Admin API"],
    )
    def put(self, request, *args, **kwargs):
        user = request.user

        # Ensure the user is a superuser
        if not user.is_superuser:
            return CustomResponse.error(message="Permission Denied.", status=403)

        try:
            # Fetch the admin's UserProfile instance
            profile = user_models.UserProfile.objects.get(user=user)
        except user_models.UserProfile.DoesNotExist:
            return CustomResponse.error(message="Profile not found.", status=404)

        serializer = self.get_serializer(data=request.data, instance=profile)
        serializer.is_valid(raise_exception=True)

        # Save the updated profile
        serializer.update(instance=profile, validated_data=serializer.validated_data)
        return CustomResponse.success(
            message="Profile updated successfully.", data=serializer.data
        )


# <----------------------------With Serializer Implemented----------------------------->


# <----------------------------Admin Dashboard API View Starts From Here--------------------------->
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
        total_category = core_models.Category.objects.count()
        total_products = core_models.Product.objects.count()
        total_customers = user_models.User.objects.filter(
            is_active=True, is_staff=False
        ).count()
        total_orders = core_models.Order.objects.count()

        # Prepare data
        data = {
            "total_category": total_category,
            "total_products": total_products,
            "total_customers": total_customers,
            "total_orders": total_orders,
        }

        # Debug the data being passed
        print("DEBUG: Data being passed to serializer:", data)

        # Serialize and return data
        serializer = user_serializer.AdminDashboardSerializer(data=data)
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


class AdminCustomerViewSet(viewsets.ModelViewSet):
    """
    A viewset that provides custom `retrieve` and `list` actions.
    """

    queryset = user_models.User.objects.all()
    serializer_class = user_serializer.AdminCustomerSerializer
    permission_classes = [IsSuperuser]  # Or use your custom IsSuperuser permission
    pagination_class = pagination.UserPagination
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
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
    ordering = ["username"]

    def get_queryset(self):
        """
        Filters out superuser accounts from the queryset.
        """
        queryset = super().get_queryset().filter(is_superuser=False)
        return queryset

    @swagger_auto_schema(
        operation_description="Retrieve a single user by ID",
        responses={
            200: user_serializer.AdminCustomerSerializer,
            404: "User not found.",
            400: "Bad request.",
        },
        tags=["Admin API"],
    )
    def retrieve(self, request, pk=None):
        """
        Retrieves a single user by ID.
        """
        try:
            user = self.get_queryset().get(pk=pk)
        except user_models.User.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.serializer_class(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description="List all users",
        responses={
            200: user_serializer.AdminCustomerSerializer(many=True),
            400: "Bad request.",
        },
        tags=["Admin API"],
    )
    def list(self, request):
        """
        Lists all users with optional filters.
        """
        queryset = self.get_queryset()
        search_term = request.query_params.get("search", None)
        if search_term:
            queryset = queryset.filter(
                Q(first_name__icontains=search_term)
                | Q(phone_number__icontains=search_term)
                | Q(userprofile__city__icontains=search_term)
                | Q(userprofile__state__icontains=search_term)
                | Q(userprofile__bio__icontains=search_term)
            )

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdminCategoryAPIViewSet(viewsets.ModelViewSet):
    queryset = core_models.Category.objects.all()
    serializer_class = user_serializer.AdminCategorySerializer
    permission_classes = [IsSuperuser]  # Or use your custom IsSuperuser permission
    pagination_class = pagination.UserPagination
    parser_classes = [FormParser, MultiPartParser]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    search_fields = [
        "id",
        "title",
    ]
    ordering_fields = [
        "title",
    ]
    ordering = ["id"]

    @swagger_auto_schema(
        operation_description="category end point",
        responses={201: "Category content created successfully."},
        tags=["Admin API"],
    )
    def create(self, request, *args, **kwargs):
        try:
            response = super().create(request, *args, **kwargs)
            return CustomResponse.success(
                message="Category created successfully.",
                data=response.data,
                status_code=status.HTTP_201_CREATED,
            )
        except Exception as e:
            return CustomResponse.error(
                message=f"Error creating category: {str(e)}",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    @swagger_auto_schema(
        operation_description="Retrieve Category entries",
        responses={200: "category entries retrieved successfully.", 404: "Not Found"},
        tags=["Admin API"],
    )
    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return CustomResponse.success(
                message="category entries retrieved successfully.", data=serializer.data
            )
        except Exception as e:
            return CustomResponse.error(
                message=f"Error retrieving categories: {str(e)}"
            )

    @swagger_auto_schema(
        operation_description="Retrieve a Category entry",
        responses={200: "Category entry retrieved successfully.", 404: "Not Found"},
        tags=["Admin API"],
    )
    def retrieve(self, request, pk=None):
        try:
            categroy = self.get_object()
            serializer = self.get_serializer(categroy)
            return CustomResponse.success(
                message="Category entry retrieved successfully.", data=serializer.data
            )
        except Exception:
            return CustomResponse.error(message="Category entry not found.")

    @swagger_auto_schema(
        operation_description="Update a Category entry",
        responses={202: "Category entry updated successfully.", 404: "Not Found"},
        tags=["Admin API"],
    )
    def update(self, request, pk=None):
        try:
            category = self.get_object()
            serializer = self.get_serializer(category, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return CustomResponse.success(
                    message="category entry updated successfully.", data=serializer.data
                )
        except Exception:
            return CustomResponse.error(
                message="category entry not found.",
            )

    @swagger_auto_schema(
        operation_description="Delete a category entry",
        responses={204: "No Content", 404: "Not Found"},
        tags=["Admin API"],
    )
    def destroy(self, request, pk=None):
        try:
            category = self.get_object()
            category.delete()
            return CustomResponse.success(
                message="category entry deleted successfully."
            )
        except Exception:
            return CustomResponse.error(message="category entry not found.")


class AdminProductAPIView(generics.GenericAPIView):
    queryset = core_models.Product.objects.all()
    serializer_class = user_serializer.AdminProductSerializer
    permission_classes = [IsSuperuser]
    pagination_class = pagination.UserPagination
    parser_classes = [FormParser, MultiPartParser]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    search_fields = [
        "title",
        "discounted_price",
        "brand",
        "product__category",
    ]
    ordering_fields = [
        "title",
        "discounted_price",
        "brand",
    ]
    ordering = ["id"]

    @swagger_auto_schema(
        operation_description="prdoduct end point",
        responses={201: "Product content created successfully."},
        tags=["Admin API"],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()  # user will be set in serializer
            return CustomResponse.success(
                message="Product created successfully",
                data=serializer.data,
                status_code=status.HTTP_201_CREATED,
            )
        return CustomResponse.error(
            message="Error creating product",
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    @swagger_auto_schema(
        operation_description="Retrieve Product entries",
        responses={200: "Product entries retrieved successfully.", 404: "Not Found"},
        tags=["Admin API"],
    )
    def get(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return CustomResponse.success(
            message="Products retrieved successfully", data=serializer.data
        )


class AdminProductUpdateAPIView(generics.GenericAPIView):
    permission_classes = [IsSuperuser]
    serializer_class = user_serializer.AdminProductSerializer
    parser_classes = [FormParser, MultiPartParser]

    def get_object(self):
        product_id = self.kwargs.get("id")
        if not product_id:
            return None, CustomResponse.error(message="Product ID cannot be empty.")
        try:
            product = core_models.Product.objects.get(id=product_id)
            return product, None
        except core_models.Product.DoesNotExist:
            return None, CustomResponse.error(
                message="Product not found.", status_code=status.HTTP_404_NOT_FOUND
            )

    @swagger_auto_schema(
        operation_description="Update product by ID.",
        responses={200: "Product updated successfully.", 404: "Invalid input."},
        tags=["Admin API"],
    )
    def put(self, request, *args, **kwargs):
        product, error_response = self.get_object()
        if error_response:
            return error_response

        serializer = self.get_serializer(
            product, data=request.data, partial=True, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            return CustomResponse.success(
                message="Product updated successfully.",
                data=serializer.data,
                status_code=status.HTTP_200_OK,
            )
        return CustomResponse.error(
            message="Failed to update product.",
            errors=serializer.errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    @swagger_auto_schema(
        operation_description="Delete product by ID.",
        responses={200: "Product deleted successfully.", 404: "Product not found."},
        tags=["Admin API"],
    )
    def delete(self, request, *args, **kwargs):
        product, error_response = self.get_object()
        if error_response:
            return error_response

        product.delete()
        return CustomResponse.success(
            message="Product deleted successfully.",
        )
