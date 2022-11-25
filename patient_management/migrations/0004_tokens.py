# Generated by Django 4.1.3 on 2022-11-16 10:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('patient_management', '0003_order_lineitem_cartitem'),
    ]

    operations = [
        migrations.CreateModel(
            name='Tokens',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=100)),
                ('username', models.CharField(max_length=100)),
                ('used', models.BooleanField(default=False)),
            ],
        ),
    ]