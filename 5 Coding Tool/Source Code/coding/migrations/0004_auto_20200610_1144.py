# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2020-06-10 15:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coding', '0003_auto_20200610_1140'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cve',
            name='description',
        ),
        migrations.RemoveField(
            model_name='cveproduct',
            name='id',
        ),
        migrations.AddField(
            model_name='cve',
            name='notes',
            field=models.TextField(null=True),
        ),
        migrations.RemoveField(
            model_name='cve',
            name='cwe_tag',
        ),
        migrations.AddField(
            model_name='cve',
            name='cwe_tag',
            field=models.ManyToManyField(default=None, to='coding.CWE'),
        ),
        migrations.AlterField(
            model_name='cveproduct',
            name='name',
            field=models.CharField(default=b'', max_length=100, primary_key=True, serialize=False),
        ),
    ]
