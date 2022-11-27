from django import forms
from .models import Order, User
from .validator import validate_file_size
from django import forms
from captcha.fields import ReCaptchaField
from captcha.widgets import ReCaptchaV2Checkbox
# from captcha.fields import ReCaptchaField
# from captcha.widgets import ReCaptchaV3Checkbox

class CartForm(forms.Form):
    quantity = forms.IntegerField(initial='1')
    product_id = forms.IntegerField(widget=forms.HiddenInput)

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super(CartForm, self).__init__(*args, **kwargs)


class CheckoutForm(forms.ModelForm):
    class Meta:
        model = Order
        exclude = ('paid',)

        widgets = {
            'address': forms.Textarea(attrs={'row': 5, 'col': 8}),
        }

class SignupForm(forms.ModelForm):
    license = forms.FileField(required=False,validators=[validate_file_size])
    identity = forms.FileField(validators=[validate_file_size])
    password1 = forms.CharField(max_length = 100)
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)
    class Meta:
        model = User
        exclude = ('orgName','is_admin','is_staff','is_active','is_superuser','banned','approved','isUser',
            'description','location','contactDetails','last_login')

        
class FileForm(forms.ModelForm):
    pass



  


class FormWithCaptcha(forms.Form):
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)