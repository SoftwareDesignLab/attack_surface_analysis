# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2020-06-04 18:05
from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('coding', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CodingTagHow',
            fields=[
                ('title', models.CharField(default=b'', max_length=200, primary_key=True, serialize=False)),
                ('description', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='CodingTagWhat',
            fields=[
                ('title', models.CharField(default=b'', max_length=200, primary_key=True, serialize=False)),
                ('description', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='CodingTagWhere',
            fields=[
                ('title', models.CharField(default=b'', max_length=200, primary_key=True, serialize=False)),
                ('description', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='CVEProductName',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default=b'', max_length=100)),
                ('description', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='CVEProductType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default=b'', max_length=100)),
                ('description', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='CWE',
            fields=[
                ('name', models.CharField(default=b'', max_length=100, primary_key=True, serialize=False, validators=[django.core.validators.RegexValidator(b'CWE-\\d{3}')])),
                ('description', models.TextField()),
            ],
        ),
        migrations.RemoveField(
            model_name='codingtag',
            name='category',
        ),
        migrations.RemoveField(
            model_name='cve',
            name='references',
        ),
        migrations.AddField(
            model_name='codingtag',
            name='cves',
            field=models.ManyToManyField(default=None, to='coding.CVE'),
        ),
        migrations.AlterField(
            model_name='codingtag',
            name='consequences',
            field=models.TextField(default=b''),
        ),
        migrations.AlterField(
            model_name='codingtag',
            name='description',
            field=models.TextField(default=b''),
        ),
        migrations.AlterField(
            model_name='codingtag',
            name='mitigation',
            field=models.TextField(default=b''),
        ),
        migrations.AlterField(
            model_name='cve',
            name='cve_id',
            field=models.CharField(max_length=15, primary_key=True, serialize=False, validators=[django.core.validators.RegexValidator(b'CVE-\\d{4}-\\d{4,7}')]),
        ),
        migrations.AlterField(
            model_name='cve',
            name='cwe_tag',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, to='coding.CWE'),
        ),
        migrations.AlterField(
            model_name='cve',
            name='description',
            field=models.TextField(default=b''),
        ),
        migrations.AlterField(
            model_name='cve',
            name='published_date',
            field=models.DateField(),
        ),
        migrations.DeleteModel(
            name='NvdCWE',
        ),
        migrations.AddField(
            model_name='codingtag',
            name='how',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, to='coding.CodingTagHow'),
        ),
        migrations.AddField(
            model_name='codingtag',
            name='what',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, to='coding.CodingTagWhat'),
        ),
        migrations.AddField(
            model_name='codingtag',
            name='where',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, to='coding.CodingTagWhere'),
        ),
    ]
