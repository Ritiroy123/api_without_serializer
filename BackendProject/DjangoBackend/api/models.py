from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
from django.utils import timezone
#from api.models import User





#  Custom User Manager
class UserManager(BaseUserManager):
  def create_user(self, email, name, phone_number,  password=None, password2=None):
      """
      Creates and saves a User with the given email, name, tc and password.
      """
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email=self.normalize_email(email),
          name=name,
          phone_number=phone_number,
          
      )

      user.set_password(password)
      user.save(using=self._db)
      return user

  def create_superuser(self, email, name, phone_number,  password=None):
      
      """
      Creates and saves a superuser with the given email, name, tc and password.

      """
      
        
      user = self.create_user(
          email,
          password=password,
          name=name,
          phone_number=phone_number,
        
          
      )
      user.is_admin = True
      user.save(using=self._db)
      return user

#  Custom User Model
class User(AbstractBaseUser):
  email = models.EmailField(
      verbose_name='Email',
      max_length=255,
      unique=True,
  )
  name = models.CharField(max_length=200)
  phone_number =models.CharField(max_length=12)
  #profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['name', 'phone_number']

  def __str__(self):
      return self.email

  def has_perm(self, perm, obj=None):
      "Does the user have a specific permission?"
      # Simplest possible answer: Yes, always
      return self.is_admin

  def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

  @property
  def is_staff(self):
      "Is the user a member of staff?"
      # Simplest possible answer: All admins are staff
      return self.is_admin
  

class checklist(models.Model):
    project_number = models.TextField(default = None,blank=False,null=False)
    subcontractor_name = models.TextField(default = None,blank=False,null=False)
    supervisor_name = models.TextField(default = None,blank=False,null=False)
    project_location = models.TextField(default = None,blank=False,null=False)
    worker_name = models.TextField(default = None,blank=False,null=False)
    work_start_end_date = models.DateField(default=None,null=False)
    log_book_material = models.TextField(default = None,blank=False,null=False)
    before_entry_bag_check = models.TextField(default = None,blank=False,null=False)
    before_entry_clothing_and_appearance = models.TextField(default = None,blank=False,null=False) 
    before_entry_tools_and_equipments_check = models.TextField(default = None,blank=False,null=False)
    physical_health = models.TextField(default = None,blank=False,null=False)
    mental_health = models.TextField(default = None,blank=False,null=False)
    before_entry_safety_helmet_check=  models.TextField(default = None,blank=False,null=False)
    before_entry_safety_shoes_check = models.TextField(default = None,blank=False,null=False)
    before_entry_safety_jackets_check = models.TextField(default = None,blank=False,null=False)
    before_entry_tobacco_and_alcohol = models.TextField(default = None,blank=False,null=False)
    before_entry_ladders_health_check = models.TextField(default = None,blank=False,null=False)
    material_logbook_check = models.TextField(default = None,blank=False,null=False)
    work_place_orderliness = models.TextField(default = None,blank=True,null=True)
    material_deposited_in_required_area =  models.TextField(default = None,blank=True,null=True)
    ladders_placement_check = models.TextField(default = None,blank=True,null=True)
    before_exit_bag_check = models.TextField(default = None,blank=True,null=True)
    before_exit_tools_and_equipments_check =  models.TextField(default = None,blank=True,null=True) 
    before_entry_remark = models.TextField(default = None,blank=True,null=True)
    before_exit_remark = models.TextField(default = None,blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auto_increment_id = models.AutoField(primary_key=True,default=None)
    user = models.ForeignKey(User,on_delete=models.CASCADE,blank=True,null=True)
    #is_true = models.BooleanField(default=False)

    def __str__(self):
      return self.project_number



  


  
