from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.conf import settings
import jwt
from django.contrib.auth import authenticate
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.serializers import Serializer
from .models import checklist,User

#from .models import Image
User = get_user_model()


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email','name','phone_number' 'profile_picture']


class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']


class  RegisterSerializer(serializers.ModelSerializer):
  # We are writing this becoz we need confirm password field in our Registratin Request
  password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
  class Meta:
    model = User
    fields=['email', 'name', 'password', 'password2', 'phone_number']
    extra_kwargs={
      'password':{'write_only':True}
    }

  # Validating Password and Confirm Password while Registration
  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    return attrs
   
  def create(self, validated_data):
    email = validated_data['email']
    password = validated_data['password']
    if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("User with this email already exists.")
    user = User.objects.create(
      email=validated_data['email'],
      name=validated_data['name'],

      phone_number=validated_data['phone_number']
      

    )
    user.set_password(password)
    '''token = jwt.encode({'user_id': user.id}, settings.SECRET_KEY, algorithm='HS256')
    send_mail(
            'Account Verification',
            f'Click the following link to verify your email: http://localhost:3000/login?token={token}',
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )'''
    
    user.save()
    return user

class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        try:
            payload = jwt.decode(value, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            user.is_active = True
            user.save()
            return value
        except jwt.ExpiredSignatureError:
            raise serializers.ValidationError('Verification link has expired.')
        except jwt.exceptions.DecodeError:
            raise serializers.ValidationError('Invalid verification token,Please register again')
        except User.DoesNotExist:
            raise serializers.ValidationError('User not found.')  
        

class UserPasswordChangeSerializer(Serializer):
    old_password = serializers.CharField(required=True, max_length=30)
    password = serializers.CharField(required=True, max_length=30)
    confirmed_password = serializers.CharField(required=True, max_length=30)

    def validate(self, data):
        # add here additional check for password strength if needed
        if not self.context['request'].user.check_password(data.get('old_password')):
            raise serializers.ValidationError({'old_password': 'Wrong password.'})

        if data.get('confirmed_password') != data.get('password'):
            raise serializers.ValidationError({'password': 'Password must be confirmed correctly.'})

        return data

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance

    def create(self, validated_data):
        pass

    @property
    def data(self):
        # just return success dictionary. you can change this to your need, but i dont think output should be user data after password change
        return {'Success': True}
class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']

  def validate(self, attrs):
    email = attrs.get('email')
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://localhost:3000/forget-password?id='+uid+'&token='+token
      send_mail(
            'Account Verification',
            f'Click Following Link to Reset Your Password '+link,
            settings.EMAIL_HOST_USER,
            [user.email],
            fail_silently=False,
        )
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')      
    

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user,token)
      raise serializers.ValidationError('Token is not Valid or Expired')
    

    

class workInfoSerializer(serializers.ModelSerializer):
     #user = UserLoginSerializer(required=False) 
     
     class Meta:
        model = checklist
        fields = ('project_number','subcontractor_name','supervisor_name','project_location','worker_name','work_start_end_date','log_book_material','before_entry_bag_check','before_entry_clothing_and_appearance','before_entry_tools_and_equipments_check','physical_health','mental_health','before_entry_safety_helmet_check','before_entry_safety_shoes_check','before_entry_safety_jackets_check','before_entry_tobacco_and_alcohol','before_entry_ladders_health_check','material_logbook_check','before_entry_remark')
      

class getidSerializer(serializers.ModelSerializer):
    class Meta:
        model = checklist
        fields = ('auto_increment_id','work_start_end_date','worker_name')     
        

class detailsSerializer(serializers.ModelSerializer):
   class Meta:
      model = checklist
      fields = ('work_place_orderliness','material_deposited_in_required_area','ladders_placement_check','before_exit_bag_check','before_exit_tools_and_equipments_check','before_exit_remark')


class AllSerializer(serializers.ModelSerializer):
   class Meta:
      model = checklist
      fields = ('__all__')