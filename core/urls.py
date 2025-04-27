from django.urls import path
from core import views

app_name = "core"



urlpatterns = [
    path('', views.HomeTemplateView.as_view(), name="home"),
    path('store/', views.StoretemplateView.as_view(), name="store"),
    path('store/<slug:category_title>/', views.StoretemplateView.as_view(), name="products_by_category"),
    path('productdetail/<int:pk>/', views.ProductDetailView.as_view(), name="productdetail"),
    path('addtocart/', views.AddToCartTemplateView.as_view(), name="add_to_cart"),
    path('checkout/', views.CheckoutCreateView.as_view(), name="checkout"),
    path('payment/<int:pk>/', views.PaymentCreateView.as_view(), name='payment'),
    path('paymentcheckoutsession/', views.CreateCheckoutSessionView.as_view(), name="paymentcheckoutsession"),
    path('paymentsuccess/', views.PaymentSuccessView.as_view(), name="paymentsuccess"),
    path('paymentcancel/', views.PaymentCancelView.as_view(), name="paymentcancel"),
    path('payment/webhook/stripe/', views.my_webhook_view, name='webhook-stripe'),
    path('invoice/<int:pk>/', views.InvoiceDetailView.as_view(), name="invoice"),
    path('customerdashboard/', views.CustomerDashboardTemplateView.as_view(), name="customerdashboard"),
    path('customerorders/', views.CustomerOrdersListView.as_view(), name="customerorders"),
    path('customerprofile/', views.CustomerProfileTemplateView.as_view(), name="customerprofile"),
    path('customer-edit-profile/<int:pk>/', views.CustomerProfileUpdateView.as_view(), name="customer-edit-profile"),
    path('generatepdf/<int:pk>', views.GeneratePdf.as_view(), name="generatepdf"),

    #<------------------------------Ajax Urls Starts From Here------------------------------->
    path('pluscart/', views.plus_cart, name='plus-click'),
    path('minuscart/', views.minus_cart, name="minus-click"),
    path('removecart/', views.remove_cart, name="remove-cart"),
]
