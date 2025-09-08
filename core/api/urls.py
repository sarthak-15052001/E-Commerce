from django.urls import path

from core.api import views as views

urlpatterns = [
    path("api/user/signup/", views.SignupView.as_view(), name="signup"),
    path("api/user/token/", views.LoginAPIView.as_view(), name="login"),
    path(
        "api/user/verify-email/<uuid:token>/",
        views.VerifyEmailView.as_view(),
        name="verify-email",
    ),
    path(
        "api/user/refresh-token/",
        views.CustomTokenRefreshView.as_view(),
        name="refresh-token",
    ),
    path(
        "api/user/forgotpassword/",
        views.ForgotPasswordAPIView.as_view(),
        name="forgotpassword",
    ),
    path(
        "api/user/reset-password/<str:token>",
        views.ResetPasswordView.as_view(),
        name="resetpassword",
    ),
    path(
        "api/user/change-password/",
        views.ChangePassword.as_view(),
        name="change-password",
    ),
    path("api/user/signout/", views.SignoutView.as_view(), name="signout"),
    path(
        "api/user/customer-profile/",
        views.CustomerProfileAPIView.as_view(),
        name="customer-profile",
    ),
    path(
        "api/user/update-customer-profile/<int:id>/",
        views.CustomerProfileUpdateAPIView.as_view(),
        name="update-customer-profile",
    ),
    path(
        "api/user/customer-dashboard/",
        views.CustomerUserDasboardAPIView.as_view(),
        name="customer-dashboard",
    ),
    path(
        "api/user/customer-invoice-list/",
        views.CustomerOrderHistoryAPIView.as_view(),
        name="customer-order-list",
    ),
    path(
        "api/user/customer-invoice-detail/<int:id>/",
        views.CustomerInvoiceDetailAPIView.as_view(),
        name="customer-order-detail",
    ),
    path("api/user/home-list/", views.HomeAPIView.as_view(), name="home-list"),
    path("api/user/store-list/", views.StoreAPIView.as_view(), name="store-list"),
    path(
        "api/user/product-detail/<int:pk>/",
        views.ProductDetailAPIView.as_view(),
        name="product-detail",
    ),
    path("api/user/add-cart/", views.AddToCartAPIView.as_view(), name="add-cart"),
    path(
        "api/user/cart-detail/", views.CartDetailAPIView.as_view(), name="cart-detail"
    ),
    path(
        "api/user/cart-remove/<int:id>/",
        views.RemoveFromCartAPIView.as_view(),
        name="cart-remove",
    ),
    path("api/user/checkout/", views.CheckoutAPIView.as_view(), name="checkout"),
    path(
        "api/user/checkout-list/",
        views.CheckoutListAPIView.as_view(),
        name="checkout-list",
    ),
    path("api/user/payment/<int:pk>/", views.PaymentAPIView.as_view(), name="payment"),
    path(
        "api/user/download-invoice/<int:id>/",
        views.InvoiceDownloadAPIView.as_view(),
        name="download-invoice",
    ),
]
