# Generated by Django 4.1.3 on 2022-11-25 18:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('patient_management', '0007_alter_user_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='contactDetails',
        ),
        migrations.RemoveField(
            model_name='user',
            name='description',
        ),
        migrations.RemoveField(
            model_name='user',
            name='location',
        ),
        migrations.RemoveField(
            model_name='user',
            name='orgName',
        ),
        migrations.AlterField(
            model_name='file',
            name='share',
            field=models.ManyToManyField(blank=True, related_name='SharedUsers', to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='file',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='hcpdocument',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='insuranceclaim',
            name='by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='UserBy', to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='insuranceclaim',
            name='to',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='UserTo', to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='organizationimage',
            name='organization',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='pdocument',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='pharmacyorder',
            name='by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='PhUserBy', to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='pharmacyorder',
            name='to',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='PhUserTo', to='patient_management.user'),
        ),
        migrations.AlterField(
            model_name='product',
            name='by',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='patient_management.user'),
        ),
    ]
