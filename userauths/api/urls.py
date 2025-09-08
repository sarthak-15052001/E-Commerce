from django.urls import include, path
from rest_framework.routers import DefaultRouter

from userauths.api import views
from userauths.api.views import AdminCategoryAPIViewSet, AdminCustomerViewSet

router = DefaultRouter()
(router.register(r"admin_customers", AdminCustomerViewSet, basename="customers"),)
(router.register(r"admin_category", AdminCategoryAPIViewSet, basename="category"),)


urlpatterns = [
    path("api/admin/profile/", views.AdminProfileView.as_view(), name="admin-profile"),
    path(
        "api/admin/dashboard/", views.AdminDasboardAPIView.as_view(), name="dashboard"
    ),
    path("api/admin/product/", views.AdminProductAPIView.as_view(), name="products"),
    path(
        "api/admin/update-product/<int:id>/",
        views.AdminProductUpdateAPIView.as_view(),
        name="update-product",
    ),
    path("api/", include(router.urls)),
]
