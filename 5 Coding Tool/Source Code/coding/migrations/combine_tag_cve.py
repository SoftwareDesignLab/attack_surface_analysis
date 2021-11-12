from django.db import migrations
from django.core.exceptions import ObjectDoesNotExist

def combine_names(apps, schema_editor):
    CVE = apps.get_model('coding', 'CVE')
    for cve in CVE.objects.all():
        try:
            coding_tag = CodingTag.objects.get(title=cve.cve_id)
            cve.where = coding_tag.where
            cve.what = coding_tag.what
            cve.how = coding_tag.how
            cve.notes = coding_tag.description
            cve.consequences = coding_tag.consequences
            cve.mitigation = coding_tag.mitigation
            cve.save()
        except ObjectDoesNotExist:
            pass

class Migration(migrations.Migration):

    dependencies = [
        ('coding', '0009_auto_20200622_1128'),
    ]

    operations = [
        migrations.RunPython(combine_names),
    ]