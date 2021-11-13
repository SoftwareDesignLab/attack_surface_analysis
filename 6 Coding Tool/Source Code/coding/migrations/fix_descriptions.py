from django.db import migrations

def combine_names(apps, schema_editor):
    CVE = apps.get_model('coding', 'CVE')
    for cve in CVE.objects.all():
        if len(cve.notes) >= 7:
            cve.notes = cve.notes[3:-4]
        if len(cve.consequences) >= 7:
            cve.consequences = cve.consequences[3:-4]
        if len(cve.mitigation) >= 7:
            cve.mitigation = cve.mitigation[3:-4]
        cve.save()

class Migration(migrations.Migration):

    dependencies = [
        ('coding', 'combine_tag_cve'),
    ]

    operations = [
        migrations.RunPython(combine_names),
    ]