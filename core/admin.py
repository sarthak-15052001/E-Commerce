from django.contrib import admin
from django.utils.safestring import mark_safe
from .models import *



@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'title', 'display_category_image']

    def display_category_image(self, obj):
        if obj.category_image:
            return mark_safe('<img src="{}" width="50px" height="50px" />'.format(obj.category_image.url))
        return None
    
    display_category_image.short_description = 'Category Image'


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'category_name', 'title', 'display_product_image', 'selling_price', 'discounted_price', 'description', 'brand']


    def display_product_image(self, obj):
        if obj.product_image:
            return mark_safe('<img src="{}" width="50px" height="50px" />'.format(obj.product_image.url))
        return None    
    display_product_image.short_description = 'Product Image'

    
    def category_name(self,obj):
        return obj.category.title
    

@admin.register(Cart)
class  CartAdmin(admin.ModelAdmin):
    list_display = ['id', 'user',  'product_name', 'quantity']

    def product_name(self, obj):
        return obj.product.title


@admin.register(Order)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'cart', 'first_name', 'last_name', 'address', 'city', 'zipcode', 'state']


@admin.register(OrderProduct)
class OrderProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'Order', 'product_name', 'quantity', 'amount', 'total_amount']

    def product_name(self, obj):
        return obj.product.title
    

@admin.register(Payment)
class paymentAdmin(admin.ModelAdmin):
    list_display = ['id', 'order_id', 'payment_type', 'user', 'orderproduct', 'made_on', 'total_amount']