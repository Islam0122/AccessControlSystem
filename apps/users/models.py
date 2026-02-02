from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
import bcrypt


class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None, **extra_fields):
        if not email:
            raise ValueError("Email обязателен")

        email = self.normalize_email(email)
        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            **extra_fields
        )

        if password:
            user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser должен иметь is_staff=True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser должен иметь is_superuser=True")

        return self.create_user(email, first_name, last_name, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Кастомная модель пользователя с аутентификацией через email.

    Поля:
    - email: Уникальный email адрес для входа
    - first_name: Имя пользователя
    - last_name: Фамилия пользователя
    - password: Хешированный пароль (bcrypt)
    - is_verified: Подтверждён ли email через OTP
    - is_active: Активен ли аккаунт (для мягкого удаления)
    - is_staff: Доступ в админ-панель Django
    - date_joined: Дата регистрации
    - last_login: Дата последнего входа
    - otp_code: Код подтверждения email (6 цифр)
    - otp_expires_at: Срок действия OTP кода
    """

    first_name = models.CharField(
        max_length=50,
        verbose_name="Имя",
        help_text="Имя пользователя (до 50 символов)"
    )
    last_name = models.CharField(
        max_length=50,
        verbose_name="Фамилия",
        help_text="Фамилия пользователя (до 50 символов)"
    )
    email = models.EmailField(
        unique=True,
        db_index=True,
        verbose_name="Email адрес",
        help_text="Уникальный email для входа в систему"
    )
    password = models.CharField(
        max_length=255,
        verbose_name="Пароль",
        help_text="Хешированный пароль (bcrypt)"
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name="Email подтверждён",
        help_text="True, если пользователь подтвердил email через OTP код"
    )
    is_active = models.BooleanField(
        default=True,
        verbose_name="Активен",
        help_text="False для мягкого удаления аккаунта"
    )
    is_staff = models.BooleanField(
        default=False,
        verbose_name="Доступ в админку",
        help_text="Разрешён ли доступ в Django Admin"
    )
    is_superuser = models.BooleanField(
        default=False,
        verbose_name="Суперпользователь",
        help_text="Полные права в системе"
    )
    date_joined = models.DateTimeField(
        default=timezone.now,
        verbose_name="Дата регистрации",
        help_text="Автоматически устанавливается при создании"
    )
    last_login = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="Последний вход",
        help_text="Обновляется при каждом логине"
    )
    otp_code = models.CharField(
        max_length=6,
        blank=True,
        null=True,
        verbose_name="OTP код",
        help_text="6-значный код для подтверждения email"
    )
    otp_expires_at = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="Срок действия OTP",
        help_text="После этого времени OTP код становится недействительным"
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        verbose_name = "Пользователь"
        verbose_name_plural = "Пользователи"
        ordering = ['-date_joined']
        db_table = 'users'
        indexes = [
            models.Index(fields=['email'], name='idx_user_email'),
            models.Index(fields=['is_active', 'is_verified'], name='idx_user_status'),
        ]

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"

    def set_password(self, raw_password):
        if not raw_password:
            raise ValueError("Пароль не может быть пустым")

        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(raw_password.encode('utf-8'), salt)
        self.password = hashed.decode('utf-8')

    def check_password(self, raw_password):
        if not raw_password or not self.password:
            return False

        try:
            return bcrypt.checkpw(
                raw_password.encode('utf-8'),
                self.password.encode('utf-8')
            )
        except (ValueError, AttributeError):
            return False

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False


class Role(models.Model):
    name = models.CharField(
        max_length=50,
        unique=True,
        db_index=True,
        verbose_name="Название роли",
        help_text="Уникальное имя роли (например: admin, manager, user)"
    )
    description = models.TextField(
        blank=True,
        null=True,
        verbose_name="Описание роли",
        help_text="Подробное описание прав и назначения роли"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
        help_text="Автоматически устанавливается при создании"
    )

    class Meta:
        verbose_name = "Роль"
        verbose_name_plural = "Роли"
        ordering = ['name']
        db_table = 'roles'

    def __str__(self):
        return self.name


class UserRole(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="roles",
        verbose_name="Пользователь",
        help_text="Пользователь, которому назначена роль"
    )
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="users",
        verbose_name="Роль",
        help_text="Роль, назначенная пользователю"
    )
    assigned_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата назначения",
        help_text="Когда роль была назначена пользователю"
    )
    assigned_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_roles",
        verbose_name="Назначена пользователем",
        help_text="Администратор, который назначил роль"
    )

    class Meta:
        verbose_name = "Роль пользователя"
        verbose_name_plural = "Роли пользователей"
        unique_together = ("user", "role")
        ordering = ['-assigned_at']
        db_table = 'user_roles'
        indexes = [
            models.Index(fields=['user', 'role'], name='idx_user_role'),
        ]

    def __str__(self):
        return f"{self.user.email} -> {self.role.name}"