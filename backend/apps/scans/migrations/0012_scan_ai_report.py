from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0011_scan_fuzzing_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='ai_report',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
    ]
