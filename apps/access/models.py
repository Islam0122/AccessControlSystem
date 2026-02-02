from django.db import models


class BusinessElement(models.Model):
    name = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        verbose_name="Название элемента",
        help_text="Уникальное имя бизнес-элемента (например: products, orders)"
    )
    description = models.TextField(
        blank=True,
        null=True,
        verbose_name="Описание",
        help_text="Подробное описание назначения элемента"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
        help_text="Автоматически устанавливается при создании"
    )

    class Meta:
        verbose_name = "Бизнес-элемент"
        verbose_name_plural = "Бизнес-элементы"
        ordering = ['name']
        db_table = 'business_elements'

    def __str__(self):
        return self.name


class AccessRolesRules(models.Model):
    role = models.ForeignKey(
        'users.Role',
        on_delete=models.CASCADE,
        related_name='access_rules',
        verbose_name="Роль",
        help_text="Роль, для которой определяются права доступа"
    )
    element = models.ForeignKey(
        BusinessElement,
        on_delete=models.CASCADE,
        related_name='access_rules',
        verbose_name="Бизнес-элемент",
        help_text="Элемент, к которому применяются правила"
    )
    read_permission = models.BooleanField(
        default=False,
        verbose_name="Чтение своих объектов",
        help_text="Разрешено читать объекты, созданные пользователем (owner_id = user.id)"
    )
    read_all_permission = models.BooleanField(
        default=False,
        verbose_name="Чтение всех объектов",
        help_text="Разрешено читать все объекты независимо от владельца"
    )

    create_permission = models.BooleanField(
        default=False,
        verbose_name="Создание",
        help_text="Разрешено создавать новые объекты"
    )

    update_permission = models.BooleanField(
        default=False,
        verbose_name="Обновление своих объектов",
        help_text="Разрешено обновлять свои объекты (owner_id = user.id)"
    )
    update_all_permission = models.BooleanField(
        default=False,
        verbose_name="Обновление всех объектов",
        help_text="Разрешено обновлять любые объекты независимо от владельца"
    )

    delete_permission = models.BooleanField(
        default=False,
        verbose_name="Удаление своих объектов",
        help_text="Разрешено удалять свои объекты (owner_id = user.id)"
    )
    delete_all_permission = models.BooleanField(
        default=False,
        verbose_name="Удаление всех объектов",
        help_text="Разрешено удалять любые объекты независимо от владельца"
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
        help_text="Когда правило было создано"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Дата обновления",
        help_text="Когда правило было последний раз изменено"
    )

    class Meta:
        verbose_name = "Правило доступа"
        verbose_name_plural = "Правила доступа"
        unique_together = ('role', 'element')
        ordering = ['role__name', 'element__name']
        db_table = 'access_roles_rules'
        indexes = [
            models.Index(fields=['role', 'element'], name='idx_role_element'),
        ]

    def __str__(self):
        return f"{self.role.name} -> {self.element.name}"

    def get_permissions_summary(self):
        perms = []

        if self.read_all_permission:
            perms.append("Читать все")
        elif self.read_permission:
            perms.append("Читать свои")

        if self.create_permission:
            perms.append("Создавать")

        if self.update_all_permission:
            perms.append("Редактировать все")
        elif self.update_permission:
            perms.append("Редактировать свои")

        if self.delete_all_permission:
            perms.append("Удалять все")
        elif self.delete_permission:
            perms.append("Удалять свои")

        return ", ".join(perms) if perms else "Нет прав"

    def save(self, *args, **kwargs):
        # Логика: read_all -> read
        if self.read_all_permission and not self.read_permission:
            self.read_permission = True

        # Логика: update_all -> update
        if self.update_all_permission and not self.update_permission:
            self.update_permission = True

        # Логика: delete_all -> delete
        if self.delete_all_permission and not self.delete_permission:
            self.delete_permission = True

        super().save(*args, **kwargs)