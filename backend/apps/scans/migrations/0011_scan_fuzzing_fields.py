from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0010_alter_report_json_url'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='fuzzing_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='scan',
            name='fuzzing_analysis',
            field=models.JSONField(blank=True, default=dict, null=True),
        ),
    ]
