# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2020-06-10 15:56
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coding', '0005_auto_20200610_1154'),
    ]

    operations = [
        migrations.AddField(
            model_name='cve',
            name='notes',
            field=models.TextField(null=True),
        ),
        migrations.AddField(
            model_name='cwe',
            name='notes',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='cve',
            name='description',
            field=models.TextField(default=None),
        ),
    ]