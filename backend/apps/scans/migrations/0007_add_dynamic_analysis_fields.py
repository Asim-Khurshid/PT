from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0006_alter_scan_hash_md5_scan_unique_user_apk'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='dynamic_analysis',
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
        migrations.AddField(
            model_name='scan',
            name='dynamic_analysis_enabled',
            field=models.BooleanField(default=False),
        ),
    ]
