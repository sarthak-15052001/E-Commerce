from django import forms
from .models import *


class CustomerProfileForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'address', 'state', 'city', 'zipcode']

    
    # def __init__(self, *args, **kwargs):
    #     super(CustomerProfileForm, self).__init__(*args, **kwargs)
                   
    #     if 'user' in self.fields:
    #         allowed_authors = User.objects.filter(is_superuser=False)
    #         self.fields['user'].queryset = allowed_authors
        

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['user', 'category', 'title', 'selling_price', 'discounted_price', 'product_image', 'description', 'brand']


    def __init__(self, *args, **kwargs):
        super(ProductForm, self).__init__(*args, **kwargs)
                   
        if 'user' in self.fields:
            allowed_authors = User.objects.filter(is_superuser=True)
            self.fields['user'].queryset = allowed_authors



class PaymentForm(forms.ModelForm):
    class Meta:
        model = Payment
        fields = ['payment_type', 'total_amount']
        widgets = {
            'payment_type': forms.Select(attrs={'class': 'form-control'}),
        }
    
    stripe_token = forms.CharField(required=False)


    def __init__(self, *args, **kwargs):
        total_amount = kwargs.pop("total_amount", None)
        super().__init__(*args, **kwargs)
        if total_amount is not None:
            self.fields['total_amount'].initial = total_amount
